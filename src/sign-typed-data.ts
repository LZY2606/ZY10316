import { arrToBufArr, ecsign, publicToAddress } from '@ethereumjs/util';
import { encode, encodePacked } from '@metamask/abi-utils';
import {
  getArrayType,
  getByteLength,
  getLength,
  isArrayType,
} from '@metamask/abi-utils/dist/parsers';
import { padStart } from '@metamask/abi-utils/dist/utils';
import {
  add0x,
  assert,
  bigIntToBytes,
  bytesToHex,
  concatBytes,
  hexToBytes,
  isStrictHexString,
  numberToBytes,
  signedBigIntToBytes,
  stringToBytes,
} from '@metamask/utils';
import { keccak256 } from 'ethereum-cryptography/keccak';

import {
  concatSig,
  isNullish,
  legacyToBuffer,
  recoverPublicKey,
} from './utils';

/**
 * This is the message format used for `V1` of `signTypedData`.
 */
export type TypedDataV1 = TypedDataV1Field[];

/**
 * This represents a single field in a `V1` `signTypedData` message.
 *
 * @property name - The name of the field.
 * @property type - The type of a field (must be a supported Solidity type).
 * @property value - The value of the field.
 */
export type TypedDataV1Field = {
  name: string;
  type: string;
  value: any;
};

/**
 * Represents the version of `signTypedData` being used.
 *
 * V1 is based upon [an early version of
 * EIP-712](https://github.com/ethereum/EIPs/pull/712/commits/21abe254fe0452d8583d5b132b1d7be87c0439ca)
 * that lacked some later security improvements, and should generally be neglected in favor of
 * later versions.
 *
 * V3 is based on EIP-712, except that arrays and recursive data structures are not supported.
 *
 * V4 is based on EIP-712, and includes full support of arrays and recursive data structures.
 */
export enum SignTypedDataVersion {
  V1 = 'V1',
  V3 = 'V3',
  V4 = 'V4',
}

export type MessageTypeProperty = {
  name: string;
  type: string;
};

export type MessageTypes = {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  EIP712Domain: MessageTypeProperty[];
  [additionalProperties: string]: MessageTypeProperty[];
};

/**
 * This is the message format used for `signTypeData`, for all versions
 * except `V1`.
 *
 * @template T - The custom types used by this message.
 * @property types - The custom types used by this message.
 * @property primaryType - The type of the message.
 * @property domain - Signing domain metadata. The signing domain is the intended context for the
 * signature (e.g. the dapp, protocol, etc. that it's intended for). This data is used to
 * construct the domain seperator of the message.
 * @property domain.name - The name of the signing domain.
 * @property domain.version - The current major version of the signing domain.
 * @property domain.chainId - The chain ID of the signing domain.
 * @property domain.verifyingContract - The address of the contract that can verify the signature.
 * @property domain.salt - A disambiguating salt for the protocol.
 * @property message - The message to be signed.
 */
export type TypedMessage<T extends MessageTypes> = {
  types: T;
  primaryType: keyof T;
  domain: {
    name?: string;
    version?: string;
    chainId?: number;
    verifyingContract?: string;
    salt?: ArrayBuffer;
  };
  message: Record<string, unknown>;
};

export const TYPED_MESSAGE_SCHEMA = {
  type: 'object',
  properties: {
    types: {
      type: 'object',
      additionalProperties: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            type: { type: 'string' },
          },
          required: ['name', 'type'],
        },
      },
    },
    primaryType: { type: 'string' },
    domain: { type: 'object' },
    message: { type: 'object' },
  },
  required: ['types', 'primaryType', 'domain', 'message'],
};

/**
 * Validate that the given value is a valid version string.
 *
 * @param version - The version value to validate.
 * @param allowedVersions - A list of allowed versions. If omitted, all versions are assumed to be
 * allowed.
 */
function validateVersion(
  version: SignTypedDataVersion,
  allowedVersions?: SignTypedDataVersion[],
) {
  if (!Object.keys(SignTypedDataVersion).includes(version)) {
    throw new Error(`Invalid version: '${version}'`);
  } else if (allowedVersions && !allowedVersions.includes(version)) {
    throw new Error(
      `SignTypedDataVersion not allowed: '${version}'. Allowed versions are: ${allowedVersions.join(
        ', ',
      )}`,
    );
  }
}

/**
 * Parse a string, number, or bigint value into a `Uint8Array`.
 *
 * @param type - The type of the value.
 * @param value - The value to parse.
 * @returns The parsed value.
 */
function parseNumber(type: string, value: string | number | bigint) {
  assert(
    value !== null,
    `Unable to encode value: Invalid number. Expected a valid number value, but received "${value}".`,
  );

  const bigIntValue = BigInt(value);

  const length = getLength(type);
  const maxValue = BigInt(2) ** BigInt(length) - BigInt(1);

  // Note that this is not accurate, since the actual maximum value for unsigned
  // integers is `2 ^ (length - 1) - 1`, but this is required for backwards
  // compatibility with the old implementation.
  assert(
    bigIntValue >= -maxValue && bigIntValue <= maxValue,
    `Unable to encode value: Number "${value}" is out of range for type "${type}".`,
  );

  return bigIntValue;
}

/**
 * Normalize a value for the Solidity `bool` type. Only real booleans and the
 * exact strings `'true'` and `'false'` are accepted; anything else is rejected.
 *
 * The previous `Boolean(value)` implementation was a signing footgun: every
 * non-empty string is truthy, so a `bool` field supplied as the string
 * `'false'` was signed as `true` while UIs stringifying the raw value displayed
 * `'false'`. Rejecting ambiguous input keeps the signed value consistent with
 * what was requested.
 *
 * @param value - The value to normalize.
 * @returns The normalized boolean.
 * @throws If the value is not a boolean or the string `'true'` or `'false'`.
 */
function normalizeBool(value: unknown): boolean {
  if (typeof value === 'boolean') {
    return value;
  }

  if (value === 'true') {
    return true;
  }

  if (value === 'false') {
    return false;
  }

  throw new Error(
    `Unable to encode value: Invalid bool. Expected a boolean or the string "true" or "false", but received "${String(
      value,
    )}".`,
  );
}

/**
 * Parse an address string to a `Uint8Array`. The behaviour of this is quite
 * strange, in that it does not parse the address as hexadecimal string, nor as
 * UTF-8. It does some weird stuff with the string and char codes, and then
 * returns the result as a `Uint8Array`.
 *
 * This is based on the old `ethereumjs-abi` implementation, which essentially
 * calls `new BN(address, 10)` on the address string, the equivalent of calling
 * `parseInt(address, 10)` in JavaScript. This is not a valid way to parse an
 * address and would result in `NaN` in plain JavaScript, but it is the
 * behaviour of the old implementation, and so we must preserve it for backwards
 * compatibility.
 *
 * @param address - The address to parse.
 * @returns The parsed address.
 */
function reallyStrangeAddressToBytes(address: string): Uint8Array {
  let addressValue = BigInt(0);

  for (let i = 0; i < address.length; i++) {
    const character = BigInt(address.charCodeAt(i) - 48);
    addressValue *= BigInt(10);

    // 'a'
    if (character >= 49) {
      addressValue += character - BigInt(49) + BigInt(0xa);

      // 'A'
    } else if (character >= 17) {
      addressValue += character - BigInt(17) + BigInt(0xa);

      // '0' - '9'
    } else {
      addressValue += character;
    }
  }

  return padStart(bigIntToBytes(addressValue), 20);
}

/**
 * The encoded representation of a single field: the ABI type of the encoded
 * value and the value itself.
 */
type EncodedField = [
  type: string,
  value: bigint | Buffer | boolean | string | Uint8Array,
];

/**
 * The value of a single field, as encoded by the field encoder.
 */
type EncodedFieldValue = EncodedField[1];

/**
 * A precompiled description of a single field. The descriptor is immutable;
 * it contains schema information only and never holds message values.
 *
 * @property name - The name of the field.
 * @property type - The declared Solidity-like type of the field.
 * @property structType - The name of the referenced struct, if the field is a
 * struct (or an array of structs).
 * @property array - Whether the field is an array.
 * @property arrayBaseType - The declared type of the array items, if the field
 * is an array.
 */
type FieldDescriptor = {
  name: string;
  type: string;
  structType?: string;
  array: boolean;
  arrayBaseType?: string;
};

/**
 * A precompiled description of a struct type.
 *
 * @property fields - The descriptors of the struct's declared fields.
 * @property encodeType - The `encodeType` string of the struct.
 * @property typeHash - The keccak256 hash of the `encodeType` string.
 */
type StructDescriptor = {
  fields: FieldDescriptor[];
  encodeType: string;
  typeHash: Buffer;
};

/**
 * The execution context used by the encoding core. This indirection lets the
 * exact same field and struct encoding logic serve both the "direct" code path
 * (which resolves and hashes the schema on every call) and the "plan" code
 * path (which uses an immutable, precompiled schema).
 *
 * @property version - The EIP-712 version the encoding complies with.
 * @property getStruct - Get the fields declared for a struct type.
 * @property getStructDescriptor - Get the precompiled descriptor of a struct.
 * @property getTypeHash - Get the type hash of a struct.
 * @property detectCycles - Whether infinitely expanding value cycles are
 * detected and rejected. This is enabled for compiled plans; the direct code
 * path keeps its historical (on-demand) behaviour.
 * @property activeStructs - Stack of object values currently being encoded,
 * used to detect infinitely expanding value cycles. Each entry also carries
 * the field path leading to the value.
 * @property trace - The optional safe trace to append encoded struct entries to.
 */
type EncodingContext = {
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4;
  getStruct: (type: string) => MessageTypeProperty[] | undefined;
  getStructDescriptor: (type: string) => StructDescriptor;
  getTypeHash: (type: string) => Buffer;
  detectCycles: boolean;
  activeStructs: Map<Record<string, unknown>, string>;
  trace?: StructTraceEntry[];
};

/**
 * A single entry in a {@link TypedDataTrace}. It contains only type names and
 * hashes; no message values are ever recorded.
 *
 * @property type - The name of the encoded struct.
 * @property typeHash - The hash of the encoded struct's type.
 * @property structHash - The hash of the encoded struct.
 */
export type StructTraceEntry = {
  type: string;
  typeHash: Buffer;
  structHash: Buffer;
};

/**
 * The optional safe trace returned by {@link TypedDataPlan.execute}.
 */
export type TypedDataTrace = {
  domainHash?: StructTraceEntry;
  messageHash?: StructTraceEntry;
  structs: StructTraceEntry[];
};

/**
 * Encode a single field.
 *
 * @param context - The encoding context.
 * @param name - The name of the field to encode.
 * @param type - The type of the field being encoded.
 * @param value - The value to encode.
 * @param descriptor - The precompiled descriptor of the field, if available.
 * @returns Encoded representation of the field.
 */
function encodeFieldValue(
  context: EncodingContext,
  name: string,
  type: string,
  // TODO: constrain type on `value`
  value: any,
  descriptor?: FieldDescriptor,
): EncodedField {
  const { version } = context;

  const fieldType = descriptor?.type ?? type;
  const isArray = descriptor?.array ?? (!descriptor && type.endsWith(']'));
  const referencedStruct = descriptor?.structType;
  const structName =
    !isArray &&
    (referencedStruct !== undefined ||
      context.getStruct(fieldType) !== undefined)
      ? referencedStruct ?? fieldType
      : undefined;

  if (structName !== undefined) {
    return ['bytes32', encodeStructField(context, structName, type, value)];
  }

  // `function` is supported in `@metamask/abi-utils`, but not allowed by
  // EIP-712, so we throw an error here.
  if (type === 'function') {
    throw new Error('Unsupported or invalid type: "function"');
  }

  if (value === undefined) {
    throw new Error(`missing value for field ${name} of type ${type}`);
  }

  if (type === 'address') {
    if (typeof value === 'number') {
      return ['address', padStart(numberToBytes(value), 20)];
    } else if (isStrictHexString(value)) {
      return ['address', add0x(value)];
    } else if (typeof value === 'string') {
      return ['address', reallyStrangeAddressToBytes(value).subarray(0, 20)];
    }
  }

  if (type === 'bool') {
    return ['bool', normalizeBool(value)];
  }

  if (type === 'bytes') {
    if (typeof value === 'number') {
      value = numberToBytes(value);
    } else if (isStrictHexString(value) || value === '0x') {
      value = hexToBytes(value);
    } else if (typeof value === 'string') {
      value = stringToBytes(value);
    }
    return ['bytes32', arrToBufArr(keccak256(value))];
  }

  if (type.startsWith('bytes') && type !== 'bytes' && !type.includes('[')) {
    if (typeof value === 'number') {
      if (value < 0) {
        return ['bytes32', new Uint8Array(32)];
      }

      return ['bytes32', bigIntToBytes(BigInt(value))];
    } else if (isStrictHexString(value)) {
      return ['bytes32', hexToBytes(value)];
    }

    return ['bytes32', value];
  }

  if (type.startsWith('int') && !type.includes('[')) {
    const bigIntValue = parseNumber(type, value);
    if (bigIntValue >= BigInt(0)) {
      return ['uint256', bigIntValue];
    }

    return ['int256', bigIntValue];
  }

  if (type === 'string') {
    if (typeof value === 'number') {
      value = numberToBytes(value);
    } else {
      value = stringToBytes(value ?? '');
    }
    return ['bytes32', arrToBufArr(keccak256(value))];
  }

  if (type.endsWith(']')) {
    if (version === SignTypedDataVersion.V3) {
      throw new Error(
        'Arrays are unimplemented in encodeData; use V4 extension',
      );
    }
    const parsedType =
      descriptor?.arrayBaseType ?? type.slice(0, type.lastIndexOf('['));
    const typeValuePairs = value.map((item: any) =>
      encodeFieldValue(context, name, parsedType, item),
    );
    return [
      'bytes32',
      arrToBufArr(
        keccak256(
          encode(
            typeValuePairs.map(([t]) => t),
            typeValuePairs.map(([, v]) => v),
          ),
        ),
      ),
    ];
  }

  return [type, value];
}

/**
 * Encode the value of a struct field (or an item of an array of structs).
 *
 * In V4, a `null` or `undefined` struct value is encoded as the 32-byte zero
 * hash, as required by EIP-712. Non-null values are encoded recursively.
 *
 * @param context - The encoding context.
 * @param structType - The name of the referenced struct.
 * @param declaredType - The type as declared on the parent field.
 * @param value - The value to encode.
 * @returns The encoded struct reference.
 */
function encodeStructField(
  context: EncodingContext,
  structType: string,
  declaredType: string,
  value: any,
): Buffer | string {
  const isArray = declaredType.includes('[');
  const nullishValue =
    context.version === SignTypedDataVersion.V4 && value == null; // eslint-disable-line no-eq-null

  // Array item structs are encoded by the array branch of the field encoder;
  // only direct struct references are encoded here.
  if (!isArray && nullishValue) {
    return '0x0000000000000000000000000000000000000000000000000000000000000000';
  }

  return arrToBufArr(keccak256(encodeStruct(context, structType, value)));
}

/**
 * Encode an object by encoding and concatenating each of its members.
 *
 * @param context - The encoding context.
 * @param primaryType - The root type.
 * @param data - The object to encode.
 * @returns An encoded representation of an object.
 */
function encodeStruct(
  context: EncodingContext,
  primaryType: string,
  data: Record<string, unknown>,
): Buffer {
  if (context.detectCycles && context.activeStructs.has(data)) {
    const cyclePath = context.activeStructs.get(data) ?? primaryType;
    throw new Error(
      `Unable to encode value: Detected an infinite value cycle at "${cyclePath}". Recursive structs in the schema are supported through finite values (for example a missing or null reference), but cyclic values cannot be encoded.`,
    );
  }

  const descriptor = context.getStructDescriptor(primaryType);
  context.activeStructs.set(data, primaryType);

  const encodedTypes = ['bytes32'];
  const encodedValues: EncodedFieldValue[] = [context.getTypeHash(primaryType)];

  try {
    for (const field of descriptor.fields) {
      if (
        context.version === SignTypedDataVersion.V3 &&
        data[field.name] === undefined
      ) {
        continue;
      }
      const [type, value] = encodeFieldValue(
        context,
        field.name,
        field.type,
        data[field.name],
        field,
      );
      encodedTypes.push(type);
      encodedValues.push(value);
    }
  } finally {
    context.activeStructs.delete(data);
  }

  const encoded = arrToBufArr(encode(encodedTypes, encodedValues));

  if (context.trace) {
    const typeHash = arrToBufArr(context.getTypeHash(primaryType));
    context.trace.push({
      type: primaryType,
      typeHash,
      structHash: arrToBufArr(keccak256(encoded)),
    });
  }

  return encoded;
}

/**
 * Create the encoding context used by the direct ("non-plan") code path. The
 * direct path resolves struct definitions from the given type map and computes
 * type hashes on demand, which is the historical behaviour.
 *
 * @param types - Type definitions for all types included in the message.
 * @param version - The EIP-712 version the encoding should comply with.
 * @returns The direct encoding context.
 */
function createDirectContext(
  types: Record<string, MessageTypeProperty[]>,
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4,
): EncodingContext {
  return {
    version,
    getStruct: (type) => types[type],
    getStructDescriptor: (type) =>
      ({
        fields: types[type],
      } as StructDescriptor),
    getTypeHash: (type) => hashType(type, types),
    detectCycles: false,
    activeStructs: new Map(),
  };
}

/**
 * Encodes an object by encoding and concatenating each of its members.
 *
 * @param primaryType - The root type.
 * @param data - The object to encode.
 * @param types - Type definitions for all types included in the message.
 * @param version - The EIP-712 version the encoding should comply with.
 * @returns An encoded representation of an object.
 */
function encodeData(
  primaryType: string,
  data: Record<string, unknown>,
  types: Record<string, MessageTypeProperty[]>,
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4,
): Buffer {
  validateVersion(version, [SignTypedDataVersion.V3, SignTypedDataVersion.V4]);

  return encodeStruct(createDirectContext(types, version), primaryType, data);
}

/**
 * Encodes the type of an object by encoding a comma delimited list of its members.
 *
 * @param primaryType - The root type to encode.
 * @param types - Type definitions for all types included in the message.
 * @returns An encoded representation of the primary type.
 */
function encodeType(
  primaryType: string,
  types: Record<string, MessageTypeProperty[]>,
): string {
  let result = '';
  const unsortedDeps = findTypeDependencies(primaryType, types);
  unsortedDeps.delete(primaryType);

  const deps = [primaryType, ...Array.from(unsortedDeps).sort()];
  for (const type of deps) {
    const children = types[type];
    if (!children) {
      throw new Error(`No type definition specified: ${type}`);
    }

    result += `${type}(${types[type]
      .map(({ name, type: t }) => `${t} ${name}`)
      .join(',')})`;
  }

  return result;
}

/**
 * Finds all types within a type definition object.
 *
 * @param primaryType - The root type.
 * @param types - Type definitions for all types included in the message.
 * @param results - The current set of accumulated types.
 * @returns The set of all types found in the type definition.
 */
function findTypeDependencies(
  primaryType: string,
  types: Record<string, MessageTypeProperty[]>,
  results: Set<string> = new Set(),
): Set<string> {
  if (typeof primaryType !== 'string') {
    throw new Error(
      `Invalid findTypeDependencies input ${JSON.stringify(primaryType)}`,
    );
  }
  const match = primaryType.match(/^\w*/u) as RegExpMatchArray;
  [primaryType] = match;
  if (results.has(primaryType) || types[primaryType] === undefined) {
    return results;
  }

  results.add(primaryType);

  for (const field of types[primaryType]) {
    findTypeDependencies(field.type, types, results);
  }
  return results;
}

/**
 * Hashes an object.
 *
 * @param primaryType - The root type.
 * @param data - The object to hash.
 * @param types - Type definitions for all types included in the message.
 * @param version - The EIP-712 version the encoding should comply with.
 * @returns The hash of the object.
 */
function hashStruct(
  primaryType: string,
  data: Record<string, unknown>,
  types: Record<string, MessageTypeProperty[]>,
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4,
): Buffer {
  validateVersion(version, [SignTypedDataVersion.V3, SignTypedDataVersion.V4]);

  const encoded = encodeData(primaryType, data, types, version);
  const hashed = keccak256(encoded);
  const buf = arrToBufArr(hashed);
  return buf;
}

/**
 * Hashes the type of an object.
 *
 * @param primaryType - The root type to hash.
 * @param types - Type definitions for all types included in the message.
 * @returns The hash of the object type.
 */
function hashType(
  primaryType: string,
  types: Record<string, MessageTypeProperty[]>,
): Buffer {
  const encodedHashType = stringToBytes(encodeType(primaryType, types));
  return arrToBufArr(keccak256(encodedHashType));
}

/**
 * Removes properties from a message object that are not defined per EIP-712.
 *
 * @param data - The typed message object.
 * @returns The typed message object with only allowed fields.
 */
function sanitizeData<T extends MessageTypes>(
  data: TypedMessage<T>,
): TypedMessage<T> {
  const sanitizedData: Partial<TypedMessage<T>> = {};
  for (const key in TYPED_MESSAGE_SCHEMA.properties) {
    if (data[key]) {
      sanitizedData[key] = data[key];
    }
  }

  if ('types' in sanitizedData) {
    // TODO: Fix types
    sanitizedData.types = { EIP712Domain: [], ...sanitizedData.types } as any;
  }
  return sanitizedData as Required<TypedMessage<T>>;
}

/**
 * Create a EIP-712 Domain Hash.
 * This hash is used at the top of the EIP-712 encoding.
 *
 * @param typedData - The typed message to hash.
 * @param version - The EIP-712 version the encoding should comply with.
 * @returns The hash of the domain object.
 */
function eip712DomainHash<T extends MessageTypes>(
  typedData: TypedMessage<T>,
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4,
): Buffer {
  validateVersion(version, [SignTypedDataVersion.V3, SignTypedDataVersion.V4]);

  const sanitizedData = sanitizeData(typedData);
  const { domain } = sanitizedData;
  const domainType = { EIP712Domain: sanitizedData.types.EIP712Domain };
  return hashStruct('EIP712Domain', domain, domainType, version);
}

/**
 * Hash a typed message according to EIP-712. The returned message starts with the EIP-712 prefix,
 * which is "1901", followed by the hash of the domain separator, then the data (if any).
 * The result is hashed again and returned.
 *
 * This function does not sign the message. The resulting hash must still be signed to create an
 * EIP-712 signature.
 *
 * @param typedData - The typed message to hash.
 * @param version - The EIP-712 version the encoding should comply with.
 * @returns The hash of the typed message.
 */
function eip712Hash<T extends MessageTypes>(
  typedData: TypedMessage<T>,
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4,
): Buffer {
  validateVersion(version, [SignTypedDataVersion.V3, SignTypedDataVersion.V4]);

  const sanitizedData = sanitizeData(typedData);
  const parts = [hexToBytes('1901')];
  parts.push(eip712DomainHash(typedData, version));

  if (sanitizedData.primaryType !== 'EIP712Domain') {
    parts.push(
      hashStruct(
        // TODO: Validate that this is a string, so this type cast can be removed.
        sanitizedData.primaryType as string,
        sanitizedData.message,
        sanitizedData.types,
        version,
      ),
    );
  }
  return arrToBufArr(keccak256(concatBytes(parts)));
}

/**
 * The version bound to a compiled {@link TypedDataPlan}. Only EIP-712 based
 * versions (`V3` and `V4`) can be compiled; `V1` uses a different encoding and
 * has no reusable type schema.
 */
export type CompiledVersion = SignTypedDataVersion.V3 | SignTypedDataVersion.V4;

/**
 * The options accepted by {@link compileTypedData}.
 *
 * @property types - The custom types used by the message.
 * @property primaryType - The type of the message.
 * @property version - The EIP-712 version the plan is bound to.
 */
export type CompileTypedDataOptions<T extends MessageTypes> = {
  types: T;
  primaryType: keyof T | string;
  version: CompiledVersion;
};

/**
 * The options accepted by {@link TypedDataPlan.execute}.
 *
 * @property domain - Signing domain metadata.
 * @property message - The message to be signed.
 * @property trace - Whether to return a safe trace of the encoding.
 */
export type ExecuteTypedDataOptions = {
  domain?: Record<string, unknown>;
  message?: Record<string, unknown>;
  trace?: boolean;
};

/**
 * The result of {@link TypedDataPlan.execute}.
 *
 * @property digest - The EIP-712 digest, as a `Buffer`.
 * @property domainHash - The hash of the domain separator.
 * @property messageHash - The hash of the message, if the primary type is not
 * `EIP712Domain`.
 * @property trace - The optional safe trace.
 */
export type TypedDataPlanResult = {
  digest: Buffer;
  domainHash: Buffer;
  messageHash?: Buffer;
  trace?: TypedDataTrace;
};

const NAME_REGEX = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;
const ARRAY_SUFFIX_REGEX = /\[(\d*)\]$/u;
const NUMBER_TYPE_REGEX =
  /^u?int(?:(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256))?$/u;
const FIXED_BYTES_TYPE_REGEX = /^bytes([1-9]|[12][0-9]|3[0-2])$/u;
const ATOMIC_TYPES = new Set(['bool', 'address', 'bytes', 'string']);

/**
 * Strip the array suffix (including nested array suffixes) from a type.
 *
 * @param type - The type to strip the array suffix from.
 * @returns The base type and whether the type is an array.
 */
function getBaseType(type: string): { baseType: string; isArray: boolean } {
  let baseType = type;
  let isArray = false;
  while (ARRAY_SUFFIX_REGEX.test(baseType)) {
    isArray = true;
    baseType = baseType.replace(ARRAY_SUFFIX_REGEX, '');
  }
  return { baseType, isArray };
}

/**
 * Validate that a field type is a valid Solidity-like type, as required by
 * EIP-712. Struct references are validated separately against the declared
 * types.
 *
 * Arrays (fixed or dynamic) of any valid type are accepted for `V4`. `V3`
 * rejects arrays, matching its runtime encoding behaviour.
 *
 * @param name - The name of the field being validated.
 * @param type - The declared type of the field.
 * @param types - All declared struct types.
 * @param version - The EIP-712 version the plan is bound to.
 * @param path - The path of the struct containing the field.
 */
function validateFieldType(
  name: string,
  type: unknown,
  types: Record<string, MessageTypeProperty[]>,
  version: CompiledVersion,
  path: string,
): void {
  if (typeof type !== 'string' || type.length === 0) {
    throw new Error(
      `Unable to compile typed data schema: Invalid type for field "${path}.${name}". Expected a non-empty Solidity-like type string, but received "${String(
        type,
      )}".`,
    );
  }

  const { baseType, isArray } = getBaseType(type);

  if (isArray && version === SignTypedDataVersion.V3) {
    throw new Error('Arrays are unimplemented in encodeData; use V4 extension');
  }

  if (baseType === 'function') {
    throw new Error('Unsupported or invalid type: "function"');
  }

  if (types[baseType] !== undefined) {
    return;
  }

  if (
    ATOMIC_TYPES.has(baseType) ||
    NUMBER_TYPE_REGEX.test(baseType) ||
    FIXED_BYTES_TYPE_REGEX.test(baseType)
  ) {
    return;
  }

  throw new Error(
    `Unable to compile typed data schema: No type definition specified: ${baseType} (referenced by field "${path}.${name}" of type "${type}").`,
  );
}

/**
 * Validate a single struct definition.
 *
 * @param name - The name of the struct.
 * @param fields - The declared fields of the struct.
 * @param types - All declared struct types.
 * @param version - The EIP-712 version the plan is bound to.
 */
function validateStruct(
  name: string,
  fields: unknown,
  types: Record<string, MessageTypeProperty[]>,
  version: CompiledVersion,
): void {
  if (!Array.isArray(fields)) {
    throw new Error(
      `Unable to compile typed data schema: Type "${name}" must be an array of { name, type } fields, but received "${typeof fields}".`,
    );
  }

  const seenFields = new Set<string>();

  for (const field of fields) {
    if (
      typeof field !== 'object' ||
      field === null ||
      typeof (field as MessageTypeProperty).name !== 'string' ||
      typeof (field as MessageTypeProperty).type !== 'string'
    ) {
      throw new Error(
        `Unable to compile typed data schema: Every field of type "${name}" must be an object with a string "name" and a string "type".`,
      );
    }

    const { name: fieldName, type: fieldType } = field as MessageTypeProperty;

    if (!NAME_REGEX.test(fieldName)) {
      throw new Error(
        `Unable to compile typed data schema: Invalid field name "${fieldName}" on type "${name}". Field names must be non-empty valid identifiers.`,
      );
    }

    if (seenFields.has(fieldName)) {
      throw new Error(
        `Unable to compile typed data schema: Duplicate field name "${fieldName}" on type "${name}".`,
      );
    }
    seenFields.add(fieldName);

    validateFieldType(fieldName, fieldType, types, version, name);
  }
}

/**
 * Compile a field descriptor from a declared field.
 *
 * @param field - The declared field.
 * @param types - All declared struct types.
 * @returns The immutable field descriptor.
 */
function compileFieldDescriptor(
  field: MessageTypeProperty,
  types: Record<string, MessageTypeProperty[]>,
): FieldDescriptor {
  const { baseType, isArray } = getBaseType(field.type);
  return {
    name: field.name,
    type: field.type,
    array: isArray,
    arrayBaseType: isArray
      ? field.type.slice(0, field.type.lastIndexOf('['))
      : undefined,
    structType: types[baseType] === undefined ? undefined : baseType,
  };
}

/**
 * Compile an immutable, reusable plan for a typed data schema. Compilation
 * validates the primary type, the dependency graph, field names and
 * Solidity-like types, and precomputes the `encodeType` string, type hash and
 * per-field encoder of every struct reachable from the primary type and the
 * domain separator.
 *
 * The resulting plan is bound to the given EIP-712 version, holds no message
 * values, and can be reused concurrently for different messages.
 */
export class TypedDataPlan {
  readonly version: CompiledVersion;

  readonly primaryType: string;

  readonly types: Record<string, MessageTypeProperty[]>;

  readonly #descriptors: Map<string, StructDescriptor>;

  /**
   * Compile a typed data schema into a plan.
   *
   * @param options - The compilation options.
   * @param options.types - The custom types used by the message.
   * @param options.primaryType - The type of the message.
   * @param options.version - The EIP-712 version the plan is bound to.
   * @returns The immutable compiled plan.
   */
  static compile<T extends MessageTypes>({
    types,
    primaryType,
    version,
  }: CompileTypedDataOptions<T>): TypedDataPlan {
    validateVersion(version, [
      SignTypedDataVersion.V3,
      SignTypedDataVersion.V4,
    ]);

    if (typeof primaryType !== 'string' || primaryType.length === 0) {
      throw new Error(
        `Unable to compile typed data schema: Invalid primary type. Expected a non-empty type name, but received "${String(
          primaryType,
        )}".`,
      );
    }

    if (typeof types !== 'object' || types === null) {
      throw new Error(
        'Unable to compile typed data schema: Expected an object mapping type names to field arrays.',
      );
    }

    const normalizedTypes: Record<string, MessageTypeProperty[]> = {
      EIP712Domain: [],
      ...(types as Record<string, MessageTypeProperty[]>),
    };

    for (const [name, fields] of Object.entries(normalizedTypes)) {
      validateStruct(name, fields, normalizedTypes, version);
    }

    if (normalizedTypes[primaryType] === undefined) {
      throw new Error(`No type definition specified: ${primaryType}`);
    }

    const reachable = new Set<string>();
    for (const rootType of ['EIP712Domain', primaryType]) {
      for (const dependency of findTypeDependencies(
        rootType,
        normalizedTypes,
      )) {
        reachable.add(dependency);
      }
    }

    const descriptors = new Map<string, StructDescriptor>();
    for (const name of reachable) {
      const encodedType = encodeType(name, normalizedTypes);
      const fields = normalizedTypes[name].map((field) =>
        compileFieldDescriptor(field, normalizedTypes),
      );
      descriptors.set(name, {
        fields,
        encodeType: encodedType,
        typeHash: arrToBufArr(keccak256(stringToBytes(encodedType))),
      });
    }

    return new TypedDataPlan(
      version,
      primaryType,
      normalizedTypes,
      descriptors,
    );
  }

  constructor(
    version: CompiledVersion,
    primaryType: string,
    types: Record<string, MessageTypeProperty[]>,
    descriptors: Map<string, StructDescriptor>,
  ) {
    this.version = version;
    this.primaryType = primaryType;
    this.types = types;
    this.#descriptors = descriptors;
    Object.freeze(this);
  }

  /**
   * Get the `encodeType` string of a struct reachable from this plan.
   *
   * @param type - The struct type name.
   * @returns The `encodeType` string.
   */
  encodeType(type: string): string {
    return this.#getDescriptor(type).encodeType;
  }

  /**
   * Get the type hash of a struct reachable from this plan.
   *
   * @param type - The struct type name.
   * @returns The type hash.
   */
  typeHash(type: string): Buffer {
    return this.#getDescriptor(type).typeHash;
  }

  /**
   * Hash a single struct value against this plan.
   *
   * @param type - The struct type name.
   * @param value - The struct value.
   * @returns The struct hash.
   */
  hashStruct(type: string, value: Record<string, unknown>): Buffer {
    return this.#executeStruct(type, value ?? {}).structHash;
  }

  /**
   * Execute the plan against a concrete domain and message. The plan itself is
   * never mutated and the provided values are not retained.
   *
   * @param options - The execution options.
   * @param options.domain - Signing domain metadata.
   * @param options.message - The message to be signed.
   * @param options.trace - Whether to return a safe trace of the encoding.
   * @returns The EIP-712 digest and optional safe trace.
   */
  execute({
    domain = {},
    message,
    trace: includeTrace = false,
  }: ExecuteTypedDataOptions = {}): TypedDataPlanResult {
    const trace: TypedDataTrace = { structs: [] };

    const domainExecution = this.#executeStruct('EIP712Domain', domain, trace);
    trace.domainHash = domainExecution.traceEntry;
    const domainHash = domainExecution.structHash;

    let messageHash: Buffer | undefined;
    if (this.primaryType !== 'EIP712Domain') {
      if (message === undefined || message === null) {
        throw new Error(
          `Unable to encode value: Missing message of primary type "${this.primaryType}".`,
        );
      }

      const messageExecution = this.#executeStruct(
        this.primaryType,
        message,
        trace,
      );
      trace.messageHash = messageExecution.traceEntry;
      messageHash = messageExecution.structHash;
    }

    const parts = [hexToBytes('1901'), domainHash];
    if (messageHash !== undefined) {
      parts.push(messageHash);
    }
    const digest = arrToBufArr(keccak256(concatBytes(parts)));

    return includeTrace
      ? { digest, domainHash, messageHash, trace }
      : { digest, domainHash, messageHash };
  }

  #getDescriptor(type: string): StructDescriptor {
    const descriptor = this.#descriptors.get(type);
    if (!descriptor) {
      throw new Error(`No type definition specified: ${type}`);
    }
    return descriptor;
  }

  #executeStruct(
    type: string,
    value: Record<string, unknown>,
    trace?: TypedDataTrace,
  ): { structHash: Buffer; traceEntry: StructTraceEntry } {
    const structTraces: StructTraceEntry[] = [];
    const context: EncodingContext = {
      version: this.version,
      getStruct: (name) => this.types[name],
      getStructDescriptor: (name) => this.#getDescriptor(name),
      getTypeHash: (name) => this.#getDescriptor(name).typeHash,
      detectCycles: true,
      activeStructs: new Map(),
      trace: structTraces,
    };

    const encoded = encodeStruct(context, type, value);
    const structHash = arrToBufArr(keccak256(encoded));
    const traceEntry = structTraces[structTraces.length - 1] ?? {
      type,
      typeHash: this.#getDescriptor(type).typeHash,
      structHash,
    };

    if (trace) {
      trace.structs.push(...structTraces);
    }

    return { structHash, traceEntry };
  }
}

/**
 * Compile a typed data schema into an immutable {@link TypedDataPlan}.
 *
 * @param options - The compilation options.
 * @returns The compiled plan.
 */
export function compileTypedData<T extends MessageTypes>(
  options: CompileTypedDataOptions<T>,
): TypedDataPlan {
  return TypedDataPlan.compile(options);
}

/**
 * A collection of utility functions used for signing typed data.
 */
export const TypedDataUtils = {
  encodeData,
  encodeType,
  findTypeDependencies,
  hashStruct,
  hashType,
  sanitizeData,
  eip712Hash,
  eip712DomainHash,
};

/**
 * Generate the "V1" hash for the provided typed message.
 *
 * The hash will be generated in accordance with an earlier version of the EIP-712
 * specification. This hash is used in `signTypedData_v1`.
 *
 * @param typedData - The typed message.
 * @returns The '0x'-prefixed hex encoded hash representing the type of the provided message.
 */
export function typedSignatureHash(typedData: TypedDataV1Field[]): string {
  const hashBuffer = _typedSignatureHash(typedData);
  return bytesToHex(hashBuffer);
}

/**
 * Normalize a value, so that `@metamask/abi-utils` can handle it. This
 * matches the behaviour of the `ethereumjs-abi` library.
 *
 * @param type - The type of the value to normalize.
 * @param value - The value to normalize.
 * @returns The normalized value.
 */
function normalizeValue(type: string, value: unknown): any {
  if (isArrayType(type) && Array.isArray(value)) {
    const [innerType] = getArrayType(type);
    return value.map((item) => normalizeValue(innerType, item));
  }

  if (type === 'address') {
    if (isStrictHexString(value)) {
      return padStart(hexToBytes(value).subarray(0, 20), 20);
    }

    if (value instanceof Uint8Array) {
      return padStart(value.subarray(0, 20), 20);
    }
  }

  if (type === 'bool') {
    return normalizeBool(value);
  }

  if (type.startsWith('bytes') && type !== 'bytes') {
    const length = getByteLength(type);
    if (typeof value === 'number') {
      if (value < 0) {
        // `solidityPack(['bytesN'], [-1])` returns `0x00..00`.
        return new Uint8Array();
      }

      return numberToBytes(value).subarray(0, length);
    }

    if (isStrictHexString(value)) {
      return hexToBytes(value).subarray(0, length);
    }

    if (value instanceof Uint8Array) {
      return value.subarray(0, length);
    }
  }

  if (type.startsWith('uint')) {
    if (typeof value === 'number') {
      return Math.abs(value);
    }
  }

  if (type.startsWith('int')) {
    if (typeof value === 'number') {
      const length = getLength(type);
      return BigInt.asIntN(length, BigInt(value));
    }
  }

  return value;
}

/**
 * For some reason `ethereumjs-abi` treats `address` and `address[]` differently
 * so we need to normalize `address[]` differently.
 *
 * @param values - The values to normalize.
 * @returns The normalized values.
 */
function normalizeAddresses(values: unknown[]) {
  return values.map((value) => {
    if (typeof value === 'number') {
      return padStart(numberToBytes(value), 32);
    }

    if (isStrictHexString(value)) {
      return padStart(hexToBytes(value).subarray(0, 32), 32);
    }

    if (value instanceof Uint8Array) {
      return padStart(value.subarray(0, 32), 32);
    }

    return value;
  });
}

/**
 * For some reason `ethereumjs-abi` treats `intN` and `intN[]` differently
 * so we need to normalize `intN[]` differently.
 *
 * @param type - The type of the value to normalize.
 * @param values - The values to normalize.
 * @returns The normalized values.
 */
function normalizeIntegers(type: string, values: unknown[]) {
  return values.map((value) => {
    if (
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'bigint'
    ) {
      const bigIntValue = parseNumber(type, value);
      if (bigIntValue >= BigInt(0)) {
        return padStart(bigIntToBytes(bigIntValue), 32);
      }

      const length = getLength(type);
      const asIntN = BigInt.asIntN(length, bigIntValue);
      return signedBigIntToBytes(asIntN, 32);
    }

    return value;
  });
}

/**
 * Generate the "V1" hash for the provided typed message.
 *
 * The hash will be generated in accordance with an earlier version of the EIP-712
 * specification. This hash is used in `signTypedData_v1`.
 *
 * @param typedData - The typed message.
 * @returns The hash representing the type of the provided message.
 */
function _typedSignatureHash(typedData: TypedDataV1): Buffer {
  const error = new Error('Expect argument to be non-empty array');
  if (
    typeof typedData !== 'object' ||
    !('length' in typedData) ||
    !typedData.length
  ) {
    throw error;
  }

  const normalizedData = typedData.map(({ name, type, value }) => {
    // Handle an edge case with `address[]` types.
    if (type === 'address[]') {
      return {
        name,
        type: 'bytes32[]',
        value: normalizeAddresses(value),
      };
    }

    // Handle an edge case with `intN[]` types.
    if (type.startsWith('int') && isArrayType(type)) {
      const [innerType, length] = getArrayType(type);
      return {
        name,
        type: `bytes32[${length ?? ''}]`,
        value: normalizeIntegers(innerType, value),
      };
    }

    return {
      name,
      type,
      value: normalizeValue(type, value),
    };
  });

  const data = normalizedData.map((e) => {
    if (e.type !== 'bytes') {
      return e.value;
    }

    return legacyToBuffer(e.value);
  });
  const types = normalizedData.map((e) => {
    if (e.type === 'function') {
      throw new Error('Unsupported or invalid type: "function"');
    }

    return e.type;
  });
  const schema = typedData.map((e) => {
    if (!e.name) {
      throw error;
    }
    return `${e.type} ${e.name}`;
  });

  return arrToBufArr(
    keccak256(
      encodePacked(
        ['bytes32', 'bytes32'],
        [
          keccak256(encodePacked(['string[]'], [schema], true)),
          keccak256(encodePacked(types, data, true)),
        ],
      ),
    ),
  );
}

/**
 * Sign typed data according to EIP-712. The signing differs based upon the `version`.
 *
 * V1 is based upon [an early version of
 * EIP-712](https://github.com/ethereum/EIPs/pull/712/commits/21abe254fe0452d8583d5b132b1d7be87c0439ca)
 * that lacked some later security improvements, and should generally be neglected in favor of
 * later versions.
 *
 * V3 is based on [EIP-712](https://eips.ethereum.org/EIPS/eip-712), except that arrays and
 * recursive data structures are not supported.
 *
 * V4 is based on [EIP-712](https://eips.ethereum.org/EIPS/eip-712), and includes full support of
 * arrays and recursive data structures.
 *
 * @param options - The signing options.
 * @param options.privateKey - The private key to sign with.
 * @param options.data - The typed data to sign.
 * @param options.version - The signing version to use.
 * @returns The '0x'-prefixed hex encoded signature.
 */
export function signTypedData<
  V extends SignTypedDataVersion,
  T extends MessageTypes,
>({
  privateKey,
  data,
  version,
}: {
  privateKey: Buffer;
  data: V extends 'V1' ? TypedDataV1 : TypedMessage<T>;
  version: V;
}): string {
  validateVersion(version);
  if (isNullish(data)) {
    throw new Error('Missing data parameter');
  } else if (isNullish(privateKey)) {
    throw new Error('Missing private key parameter');
  }

  const messageHash =
    version === SignTypedDataVersion.V1
      ? _typedSignatureHash(data as TypedDataV1)
      : TypedDataUtils.eip712Hash(data as TypedMessage<T>, version);
  const sig = ecsign(messageHash, privateKey);
  return concatSig(arrToBufArr(bigIntToBytes(sig.v)), sig.r, sig.s);
}

/**
 * Recover the address of the account that created the given EIP-712
 * signature. The version provided must match the version used to
 * create the signature.
 *
 * @param options - The signature recovery options.
 * @param options.data - The typed data that was signed.
 * @param options.signature - The '0x-prefixed hex encoded message signature.
 * @param options.version - The signing version to use.
 * @returns The '0x'-prefixed hex address of the signer.
 */
export function recoverTypedSignature<
  V extends SignTypedDataVersion,
  T extends MessageTypes,
>({
  data,
  signature,
  version,
}: {
  data: V extends 'V1' ? TypedDataV1 : TypedMessage<T>;
  signature: string;
  version: V;
}): string {
  validateVersion(version);
  if (isNullish(data)) {
    throw new Error('Missing data parameter');
  } else if (isNullish(signature)) {
    throw new Error('Missing signature parameter');
  }

  const messageHash =
    version === SignTypedDataVersion.V1
      ? _typedSignatureHash(data as TypedDataV1)
      : TypedDataUtils.eip712Hash(data as TypedMessage<T>, version);
  const publicKey = recoverPublicKey(messageHash, signature);
  const sender = publicToAddress(publicKey);
  return bytesToHex(sender);
}

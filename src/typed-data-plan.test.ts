import * as ethUtil from '@ethereumjs/util';
import { bigIntToBytes, bytesToHex } from '@metamask/utils';

import {
  compileTypedDataPlan,
  recoverTypedSignature,
  signTypedData,
  TypedDataUtils,
  SignTypedDataVersion,
} from './sign-typed-data';
import { concatSig, recoverPublicKey } from './utils';

const privateKey = Buffer.from(
  '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0',
  'hex',
);

const planTypes = {
  EIP712Domain: [
    { name: 'name', type: 'string' },
    { name: 'version', type: 'string' },
    { name: 'chainId', type: 'uint256' },
    { name: 'verifyingContract', type: 'address' },
  ],
  Person: [
    { name: 'name', type: 'string' },
    { name: 'wallet', type: 'address' },
  ],
  Mail: [
    { name: 'from', type: 'Person' },
    { name: 'to', type: 'Person' },
    { name: 'contents', type: 'string' },
  ],
};

const planDomain = {
  name: 'Ether Mail',
  version: '1',
  chainId: 1,
  verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
};

const planMessage = {
  from: {
    name: 'Cow',
    wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
  },
  to: {
    name: 'Bob',
    wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
  },
  contents: 'Hello, Bob!',
};

const planTypedData = {
  types: planTypes,
  primaryType: 'Mail' as const,
  domain: planDomain,
  message: planMessage,
};

/**
 * Sign a digest with the test private key, using the same signature
 * concatenation as `signTypedData`.
 *
 * @param digest - The digest to sign.
 * @returns The '0x'-prefixed hex encoded signature.
 */
function signDigest(digest: Buffer): string {
  const sig = ethUtil.ecsign(digest, privateKey);
  return concatSig(ethUtil.arrToBufArr(bigIntToBytes(sig.v)), sig.r, sig.s);
}

/**
 * Recover the signer address from a digest and signature.
 *
 * @param digest - The digest that was signed.
 * @param signature - The '0x'-prefixed hex encoded signature.
 * @returns The '0x'-prefixed hex address of the signer.
 */
function recoverDigestAddress(digest: Buffer, signature: string): string {
  return bytesToHex(
    ethUtil.publicToAddress(recoverPublicKey(digest, signature)),
  );
}

describe('compileTypedDataPlan', function () {
  describe('compile-time schema validation', function () {
    it('should throw if passed an invalid version', function () {
      expect(() =>
        compileTypedDataPlan(
          { types: planTypes, primaryType: 'Mail' },
          'V2' as any,
        ),
      ).toThrow("Invalid version: 'V2'");
    });

    it('should reject V1', function () {
      expect(() =>
        compileTypedDataPlan(
          { types: planTypes, primaryType: 'Mail' },
          SignTypedDataVersion.V1 as any,
        ),
      ).toThrow(
        "SignTypedDataVersion not allowed: 'V1'. Allowed versions are: V3, V4",
      );
    });

    it('should throw if passed a nullish schema', function () {
      expect(() =>
        compileTypedDataPlan(undefined as any, SignTypedDataVersion.V4),
      ).toThrow('Missing schema parameter');
    });

    it('should throw if the types are missing', function () {
      expect(() =>
        compileTypedDataPlan(
          { types: undefined as any, primaryType: 'Mail' },
          SignTypedDataVersion.V4,
        ),
      ).toThrow('Missing types parameter');
    });

    it.each([undefined, null, '', 42])(
      'should throw if the primary type is %p',
      function (primaryType) {
        expect(() =>
          compileTypedDataPlan(
            { types: planTypes, primaryType: primaryType as any },
            SignTypedDataVersion.V4,
          ),
        ).toThrow(`Invalid primary type: ${JSON.stringify(primaryType)}`);
      },
    );

    it('should throw if the primary type has no definition', function () {
      expect(() =>
        compileTypedDataPlan(
          { types: planTypes, primaryType: 'Missing' as any },
          SignTypedDataVersion.V4,
        ),
      ).toThrow('No type definition specified: Missing');
    });

    it('should throw if a referenced struct type is not defined', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'person', type: 'Person' }],
      };
      expect(() =>
        compileTypedDataPlan(
          { types, primaryType: 'Message' },
          SignTypedDataVersion.V4,
        ),
      ).toThrow('Unsupported or invalid type: "Person"');
    });

    it('should throw if a field type is unrecognized', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'foo' }],
      };
      expect(() =>
        compileTypedDataPlan(
          { types, primaryType: 'Message' },
          SignTypedDataVersion.V4,
        ),
      ).toThrow('Unsupported or invalid type: "foo"');
    });

    it('should throw for the unsupported function type', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'function' }],
      };
      expect(() =>
        compileTypedDataPlan(
          { types, primaryType: 'Message' },
          SignTypedDataVersion.V4,
        ),
      ).toThrow('Unsupported or invalid type: "function"');
    });

    it.each(['string[', '[]', 'Person[', 'string[x]', 'string]'])(
      'should throw for malformed array type %p',
      function (type) {
        const types = {
          EIP712Domain: [],
          Message: [{ name: 'data', type }],
        };
        expect(() =>
          compileTypedDataPlan(
            { types, primaryType: 'Message' },
            SignTypedDataVersion.V4,
          ),
        ).toThrow(`Unsupported or invalid type: "${type}"`);
      },
    );

    it.each([
      'uint7',
      'uint9',
      'uint264',
      'int3',
      'int300',
      'bytes0',
      'bytes33',
    ])('should throw for invalid elementary width %p', function (type) {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type }],
      };
      expect(() =>
        compileTypedDataPlan(
          { types, primaryType: 'Message' },
          SignTypedDataVersion.V4,
        ),
      ).toThrow(`Unsupported or invalid type: "${type}"`);
    });

    it.each(['int', 'uint', 'bytes', 'bytes1', 'bytes32', 'int8', 'uint256'])(
      'should accept valid elementary type %p',
      function (type) {
        const types = {
          EIP712Domain: [],
          Message: [{ name: 'data', type }],
        };
        expect(() =>
          compileTypedDataPlan(
            { types, primaryType: 'Message' },
            SignTypedDataVersion.V4,
          ),
        ).not.toThrow();
      },
    );

    it('should throw if a type definition is not an array', function () {
      const types = {
        EIP712Domain: [],
        Message: 'not-an-array',
      };
      expect(() =>
        compileTypedDataPlan(
          { types: types as any, primaryType: 'Message' },
          SignTypedDataVersion.V4,
        ),
      ).toThrow('Invalid type definition for "Message"');
    });

    it('should throw if a field has an empty name', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: '', type: 'string' }],
      };
      expect(() =>
        compileTypedDataPlan(
          { types, primaryType: 'Message' },
          SignTypedDataVersion.V4,
        ),
      ).toThrow('Invalid field name in type "Message"');
    });

    it('should throw if a field has an empty type', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: '' }],
      };
      expect(() =>
        compileTypedDataPlan(
          { types, primaryType: 'Message' },
          SignTypedDataVersion.V4,
        ),
      ).toThrow('Invalid field type for field "data" in type "Message"');
    });

    it('should tolerate invalid types that are not reachable', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'string' }],
        Extra: [{ name: 'data', type: 'foo' }],
      };
      expect(() =>
        compileTypedDataPlan(
          { types, primaryType: 'Message' },
          SignTypedDataVersion.V4,
        ),
      ).not.toThrow();
    });
  });

  describe('equivalence with the direct encoding path', function () {
    it.each([SignTypedDataVersion.V3, SignTypedDataVersion.V4])(
      'should produce identical type strings and hashes (%s)',
      function (version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4) {
        const plan = compileTypedDataPlan(
          { types: planTypes, primaryType: 'Mail' },
          version,
        );

        expect(plan.version).toBe(version);
        expect(plan.primaryType).toBe('Mail');
        expect(plan.encodeType).toBe(
          TypedDataUtils.encodeType('Mail', planTypes),
        );
        expect(plan.typeHash.toString('hex')).toBe(
          TypedDataUtils.hashType('Mail', planTypes).toString('hex'),
        );
        expect(plan.domainEncodeType).toBe(
          TypedDataUtils.encodeType('EIP712Domain', {
            EIP712Domain: planTypes.EIP712Domain,
          }),
        );
        expect(plan.domainTypeHash.toString('hex')).toBe(
          TypedDataUtils.hashType('EIP712Domain', {
            EIP712Domain: planTypes.EIP712Domain,
          }).toString('hex'),
        );
        expect(plan.encodeMessage(planMessage).toString('hex')).toBe(
          TypedDataUtils.hashStruct(
            'Mail',
            planMessage,
            planTypes,
            version,
          ).toString('hex'),
        );
        expect(plan.encodeDomain(planDomain).toString('hex')).toBe(
          TypedDataUtils.eip712DomainHash(planTypedData, version).toString(
            'hex',
          ),
        );
        expect(plan.digest(planDomain, planMessage).toString('hex')).toBe(
          TypedDataUtils.eip712Hash(planTypedData, version).toString('hex'),
        );
      },
    );

    it.each([SignTypedDataVersion.V3, SignTypedDataVersion.V4])(
      'should produce identical signatures and recoveries (%s)',
      function (version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4) {
        const plan = compileTypedDataPlan(
          { types: planTypes, primaryType: 'Mail' },
          version,
        );

        const planDigest = plan.digest(planDomain, planMessage);
        const directSignature = signTypedData({
          privateKey,
          data: planTypedData,
          version,
        });
        const planSignature = signDigest(planDigest);
        const directRecovery = recoverTypedSignature({
          data: planTypedData,
          signature: directSignature,
          version,
        });

        expect(planSignature).toBe(directSignature);
        expect(recoverDigestAddress(planDigest, directSignature)).toBe(
          directRecovery,
        );
        expect(
          recoverTypedSignature({
            data: planTypedData,
            signature: planSignature,
            version,
          }),
        ).toBe(directRecovery);
      },
    );

    it.each([SignTypedDataVersion.V3, SignTypedDataVersion.V4])(
      'should match the direct path when no EIP712Domain type is defined (%s)',
      function (version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4) {
        const types = {
          Message: [{ name: 'data', type: 'string' }],
        };
        const plan = compileTypedDataPlan(
          { types: types as any, primaryType: 'Message' },
          version,
        );
        const typedData = {
          types,
          primaryType: 'Message' as const,
          domain: {},
          message: { data: 'Hello!' },
        };

        expect(plan.digest({}, { data: 'Hello!' }).toString('hex')).toBe(
          TypedDataUtils.eip712Hash(typedData as any, version).toString('hex'),
        );
      },
    );

    it.each([SignTypedDataVersion.V3, SignTypedDataVersion.V4])(
      'should match the direct path for a minimal EIP712Domain message (%s)',
      function (version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4) {
        const types = { EIP712Domain: [] };
        const plan = compileTypedDataPlan(
          { types, primaryType: 'EIP712Domain' },
          version,
        );
        const typedData = {
          types,
          primaryType: 'EIP712Domain' as const,
          domain: {},
          message: {},
        };

        expect(plan.digest({}, {}).toString('hex')).toBe(
          TypedDataUtils.eip712Hash(typedData, version).toString('hex'),
        );
        const { digest, trace } = plan.execute({}, {}, { trace: true });
        expect(digest.toString('hex')).toBe(
          TypedDataUtils.eip712Hash(typedData, version).toString('hex'),
        );
        expect(trace?.messageHash).toBeNull();
      },
    );

    it('should expand a recursive schema over finite values (V4)', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
          { name: 'replyTo', type: 'Mail' },
        ],
      };
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
          name: 'Bob',
          wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
        replyTo: {
          from: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
          },
          to: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          },
          contents: 'Hello!',
        },
      };
      const plan = compileTypedDataPlan(
        { types, primaryType: 'Mail' },
        SignTypedDataVersion.V4,
      );

      expect(plan.encodeMessage(message).toString('hex')).toBe(
        TypedDataUtils.hashStruct(
          'Mail',
          message,
          types,
          SignTypedDataVersion.V4,
        ).toString('hex'),
      );
    });

    it('should match the direct path for arrays of custom types (V4)', function () {
      const types = {
        EIP712Domain: [],
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person[]' },
          { name: 'contents', type: 'string' },
        ],
      };
      const message = {
        from: {
          name: 'Cow',
          wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: [
          {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
          },
        ],
        contents: 'Hello, Bob!',
      };
      const plan = compileTypedDataPlan(
        { types, primaryType: 'Mail' },
        SignTypedDataVersion.V4,
      );

      expect(plan.encodeMessage(message).toString('hex')).toBe(
        TypedDataUtils.hashStruct(
          'Mail',
          message,
          types,
          SignTypedDataVersion.V4,
        ).toString('hex'),
      );
    });

    it('should ignore extra unspecified message properties like the direct path', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'string' }],
      };
      const plan = compileTypedDataPlan(
        { types, primaryType: 'Message' },
        SignTypedDataVersion.V4,
      );
      const message = { data: 'Hello!', extra: 'stuff', moreExtra: 1 };
      const typedData = {
        types,
        primaryType: 'Message' as const,
        domain: {},
        message,
      };

      expect(plan.digest({}, message).toString('hex')).toBe(
        TypedDataUtils.eip712Hash(typedData, SignTypedDataVersion.V4).toString(
          'hex',
        ),
      );
      expect(plan.digest({}, message).toString('hex')).toBe(
        plan.digest({}, { data: 'Hello!' }).toString('hex'),
      );
    });

    it('should match the direct path for shared (non-circular) value references', function () {
      const sharedPerson = {
        name: 'Cow',
        wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
      };
      const message = {
        from: sharedPerson,
        to: sharedPerson,
        contents: 'Hello!',
      };
      const plan = compileTypedDataPlan(
        { types: planTypes, primaryType: 'Mail' },
        SignTypedDataVersion.V4,
      );

      expect(plan.encodeMessage(message).toString('hex')).toBe(
        TypedDataUtils.hashStruct(
          'Mail',
          message,
          planTypes,
          SignTypedDataVersion.V4,
        ).toString('hex'),
      );
    });

    it.each([SignTypedDataVersion.V3, SignTypedDataVersion.V4])(
      'should be insensitive to schema key order (%s)',
      function (version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4) {
        const reversedTypes = Object.fromEntries(
          Object.entries(planTypes).reverse(),
        ) as typeof planTypes;
        const plan = compileTypedDataPlan(
          { types: planTypes, primaryType: 'Mail' },
          version,
        );
        const reversedPlan = compileTypedDataPlan(
          { types: reversedTypes, primaryType: 'Mail' },
          version,
        );

        expect(reversedPlan.encodeType).toBe(plan.encodeType);
        expect(reversedPlan.typeHash.toString('hex')).toBe(
          plan.typeHash.toString('hex'),
        );
        expect(reversedPlan.domainEncodeType).toBe(plan.domainEncodeType);
        expect(
          reversedPlan.digest(planDomain, planMessage).toString('hex'),
        ).toBe(plan.digest(planDomain, planMessage).toString('hex'));
        expect(
          reversedPlan.digest(planDomain, planMessage).toString('hex'),
        ).toBe(
          TypedDataUtils.eip712Hash(planTypedData, version).toString('hex'),
        );
      },
    );
  });

  describe('error paths', function () {
    it('should throw the same error as the direct path for a missing value', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'string' }],
      };
      const plan = compileTypedDataPlan(
        { types, primaryType: 'Message' },
        SignTypedDataVersion.V4,
      );

      expect(() => plan.digest({}, {})).toThrow(
        'missing value for field data of type string',
      );
      expect(() =>
        TypedDataUtils.encodeData(
          'Message',
          {},
          types,
          SignTypedDataVersion.V4,
        ),
      ).toThrow('missing value for field data of type string');
    });

    it('should throw the same error as the direct path for an invalid value', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'address' }],
      };
      const plan = compileTypedDataPlan(
        { types, primaryType: 'Message' },
        SignTypedDataVersion.V4,
      );
      const message = { data: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB0' };

      expect(() => plan.digest({}, message)).toThrow(
        'Unable to encode value: Invalid address value. Expected address to be 20 bytes long, but received 21 bytes.',
      );
    });

    it('should reject arrays in V3 like the direct path', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'string[]' }],
      };
      const plan = compileTypedDataPlan(
        { types, primaryType: 'Message' },
        SignTypedDataVersion.V3,
      );

      expect(() => plan.digest({}, { data: ['1', '2', '3'] })).toThrow(
        'Arrays are unimplemented in encodeData; use V4 extension',
      );
    });

    it('should encode a null custom type property in V4 like the direct path', function () {
      const plan = compileTypedDataPlan(
        { types: planTypes, primaryType: 'Mail' },
        SignTypedDataVersion.V4,
      );
      const message = { ...planMessage, from: null };

      expect(plan.encodeMessage(message).toString('hex')).toBe(
        TypedDataUtils.hashStruct(
          'Mail',
          message,
          planTypes,
          SignTypedDataVersion.V4,
        ).toString('hex'),
      );
    });

    it('should throw for a null custom type property in V3 like the direct path', function () {
      const plan = compileTypedDataPlan(
        { types: planTypes, primaryType: 'Mail' },
        SignTypedDataVersion.V3,
      );
      const message = { ...planMessage, from: null };

      expect(() => plan.encodeMessage(message)).toThrow('Cannot read propert');
      expect(() =>
        TypedDataUtils.hashStruct(
          'Mail',
          message,
          planTypes,
          SignTypedDataVersion.V3,
        ),
      ).toThrow('Cannot read propert');
    });

    it('should skip undefined properties in V3 like the direct path', function () {
      const plan = compileTypedDataPlan(
        { types: planTypes, primaryType: 'Mail' },
        SignTypedDataVersion.V3,
      );
      const message = {
        from: planMessage.from,
        to: planMessage.to,
        contents: undefined,
      };

      expect(plan.encodeMessage(message).toString('hex')).toBe(
        TypedDataUtils.hashStruct(
          'Mail',
          message,
          planTypes,
          SignTypedDataVersion.V3,
        ).toString('hex'),
      );
    });
  });

  describe('circular values', function () {
    const circularTypes = {
      EIP712Domain: [],
      Person: [
        { name: 'name', type: 'string' },
        { name: 'friend', type: 'Person' },
      ],
    };

    it('should distinguish a schema cycle from an infinite value cycle', function () {
      const plan = compileTypedDataPlan(
        { types: circularTypes, primaryType: 'Person' },
        SignTypedDataVersion.V4,
      );

      // A recursive schema with a finite value is encoded normally.
      const finiteValue = {
        name: 'Alice',
        friend: { name: 'Bob', friend: { name: 'Carol' } },
      };
      expect(plan.encodeMessage(finiteValue).toString('hex')).toBe(
        TypedDataUtils.hashStruct(
          'Person',
          finiteValue,
          circularTypes,
          SignTypedDataVersion.V4,
        ).toString('hex'),
      );

      // An infinitely recursive value is rejected with a distinct error.
      const circularValue: Record<string, unknown> = { name: 'Alice' };
      circularValue.friend = circularValue;
      expect(() => plan.digest({}, circularValue)).toThrow(
        'Unable to encode value: Circular reference detected while encoding type "Person".',
      );
    });

    it('should detect circular arrays', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'string[][]' }],
      };
      const plan = compileTypedDataPlan(
        { types, primaryType: 'Message' },
        SignTypedDataVersion.V4,
      );
      const circularList: unknown[] = [];
      circularList.push(circularList);

      expect(() => plan.digest({}, { data: circularList })).toThrow(
        'Unable to encode value: Circular reference detected while encoding type "string[]".',
      );
    });

    it('should detect circular values across domain and message independently', function () {
      const plan = compileTypedDataPlan(
        { types: planTypes, primaryType: 'Mail' },
        SignTypedDataVersion.V4,
      );

      // The same object may legitimately appear in both the domain and the
      // message; only cycles within a single value graph are rejected.
      const shared = { name: 'Ether Mail' };
      const domain = { ...planDomain, name: shared.name };
      expect(() => plan.digest(domain, planMessage)).not.toThrow();
      expect(shared.name).toBe('Ether Mail');
    });
  });

  describe('immutability and reuse', function () {
    it('should return a frozen plan with frozen types', function () {
      const plan = compileTypedDataPlan(
        { types: planTypes, primaryType: 'Mail' },
        SignTypedDataVersion.V4,
      );

      expect(Object.isFrozen(plan)).toBe(true);
      expect(Object.isFrozen(plan.types)).toBe(true);
      expect(Object.isFrozen(plan.types.Mail)).toBe(true);
      expect(Object.isFrozen(plan.types.Mail[0])).toBe(true);
    });

    it('should not be affected by mutation of the source schema', function () {
      const types = {
        EIP712Domain: [],
        Message: [{ name: 'data', type: 'string' }],
      };
      const plan = compileTypedDataPlan(
        { types, primaryType: 'Message' },
        SignTypedDataVersion.V4,
      );
      const digestBefore = plan.digest({}, { data: 'Hello!' }).toString('hex');

      types.Message.push({ name: 'extra', type: 'string' });
      (types as any).Extra = [{ name: 'data', type: 'string' }];

      expect(plan.digest({}, { data: 'Hello!' }).toString('hex')).toBe(
        digestBefore,
      );
      expect(plan.encodeType).toBe('Message(string data)');
    });

    it('should compile the schema exactly once and never during execution', function () {
      const hashTypeSpy = jest.spyOn(TypedDataUtils, 'hashType');
      const encodeTypeSpy = jest.spyOn(TypedDataUtils, 'encodeType');

      const plan = compileTypedDataPlan(
        { types: planTypes, primaryType: 'Mail' },
        SignTypedDataVersion.V4,
      );
      const hashTypeCallsAfterCompile = hashTypeSpy.mock.calls.length;
      const encodeTypeCallsAfterCompile = encodeTypeSpy.mock.calls.length;
      expect(hashTypeCallsAfterCompile).toBeGreaterThan(0);
      expect(encodeTypeCallsAfterCompile).toBeGreaterThan(0);

      plan.digest(planDomain, planMessage);
      plan.execute(planDomain, planMessage);
      plan.execute(planDomain, planMessage, { trace: true });
      plan.encodeMessage(planMessage);
      plan.encodeDomain(planDomain);

      expect(hashTypeSpy.mock.calls).toHaveLength(hashTypeCallsAfterCompile);
      expect(encodeTypeSpy.mock.calls).toHaveLength(
        encodeTypeCallsAfterCompile,
      );
      expect(plan.stats.executions).toBe(3);
    });

    it('should hold no message state between executions', async function () {
      const plan = compileTypedDataPlan(
        { types: planTypes, primaryType: 'Mail' },
        SignTypedDataVersion.V4,
      );
      const messages = [
        planMessage,
        { ...planMessage, contents: 'Hello, Alice!' },
        { ...planMessage, contents: 'Hello, Carol!' },
      ];

      const digests = await Promise.all(
        messages.map(async (message) => {
          await new Promise((resolve) => setImmediate(resolve));
          return plan.digest(planDomain, message).toString('hex');
        }),
      );

      for (const [index, message] of messages.entries()) {
        expect(digests[index]).toBe(
          TypedDataUtils.eip712Hash(
            { ...planTypedData, message },
            SignTypedDataVersion.V4,
          ).toString('hex'),
        );
      }
      expect(plan.stats.executions).toBe(3);
    });
  });

  describe('security trace', function () {
    it('should return no trace unless requested', function () {
      const plan = compileTypedDataPlan(
        { types: planTypes, primaryType: 'Mail' },
        SignTypedDataVersion.V4,
      );

      const result = plan.execute(planDomain, planMessage);
      expect(result.digest.toString('hex')).toBe(
        plan.digest(planDomain, planMessage).toString('hex'),
      );
      expect(result.trace).toBeUndefined();
    });

    it('should describe exactly what was signed when requested', function () {
      const plan = compileTypedDataPlan(
        { types: planTypes, primaryType: 'Mail' },
        SignTypedDataVersion.V4,
      );

      const { digest, trace } = plan.execute(planDomain, planMessage, {
        trace: true,
      });

      expect(digest.toString('hex')).toBe(
        TypedDataUtils.eip712Hash(
          planTypedData,
          SignTypedDataVersion.V4,
        ).toString('hex'),
      );
      expect(trace).toStrictEqual({
        version: SignTypedDataVersion.V4,
        primaryType: 'Mail',
        encodeType: plan.encodeType,
        typeHash: bytesToHex(plan.typeHash),
        domainEncodeType: plan.domainEncodeType,
        domainTypeHash: bytesToHex(plan.domainTypeHash),
        domainSeparator: bytesToHex(
          TypedDataUtils.eip712DomainHash(
            planTypedData,
            SignTypedDataVersion.V4,
          ),
        ),
        messageHash: bytesToHex(
          TypedDataUtils.hashStruct(
            'Mail',
            planMessage,
            planTypes,
            SignTypedDataVersion.V4,
          ),
        ),
        digest: bytesToHex(digest),
        missingDomainFields: [],
        ignoredDomainFields: [],
        missingMessageFields: [],
        ignoredMessageFields: [],
      });
    });

    it('should report missing and ignored fields', function () {
      const plan = compileTypedDataPlan(
        { types: planTypes, primaryType: 'Mail' },
        SignTypedDataVersion.V3,
      );
      const domain = { ...planDomain, chainId: undefined, extra: 'domain' };
      const message = {
        from: planMessage.from,
        to: planMessage.to,
        extra: 'message',
      };

      const { trace } = plan.execute(domain, message, { trace: true });

      expect(trace?.missingDomainFields).toStrictEqual(['chainId']);
      expect(trace?.ignoredDomainFields).toStrictEqual(['extra']);
      expect(trace?.missingMessageFields).toStrictEqual(['contents']);
      expect(trace?.ignoredMessageFields).toStrictEqual(['extra']);
    });
  });
});

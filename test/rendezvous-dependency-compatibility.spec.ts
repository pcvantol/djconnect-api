import { describe, expect, it } from 'vitest';
import * as asn from 'asn1js';
import * as pki from 'pkijs';

describe('joint ASN.1 and PKI runtime dependency boundary', () => {
	it('retains the original KeyUsage class and exact encoded bits after PKI parsing', () => {
		const bytes = new asn.BitString({ valueHex: Uint8Array.of(0x80).buffer, unusedBits: 7 }).toBER(false);
		const extension = new pki.Extension({ extnID: '2.5.29.15', critical: true, extnValue: bytes });
		const decoded = extension.parsedValue;
		expect(decoded).toBeInstanceOf(asn.BitString);
		expect(new Uint8Array(decoded.toBER(false))).toEqual(new Uint8Array(bytes));
		expect(decoded.valueBlock.unusedBits).toBe(7);
		expect(decoded.valueBlock.valueHexView).toEqual(Uint8Array.of(0x80));
	});

	it('retains the original SubjectKeyIdentifier class after PKI parsing', () => {
		const bytes = new asn.OctetString({ valueHex: Uint8Array.of(1, 2, 3).buffer }).toBER(false);
		const extension = new pki.Extension({ extnID: '2.5.29.14', extnValue: bytes });
		expect(extension.parsedValue).toBeInstanceOf(asn.OctetString);
		expect(extension.parsedValue.valueBlock.valueHexView).toEqual(Uint8Array.of(1, 2, 3));
	});

	it('accepts an ASN.1 schema built by the application in the PKI decoder', () => {
		const algorithm = new pki.AlgorithmIdentifier({
			algorithmId: '1.2.840.10045.2.1',
			algorithmParams: new asn.ObjectIdentifier({ value: '1.2.840.10045.3.1.7' }),
		});
		const parsed = new pki.AlgorithmIdentifier({ schema: algorithm.toSchema() });
		expect(parsed.algorithmId).toBe('1.2.840.10045.2.1');
		expect(parsed.algorithmParams).toBeInstanceOf(asn.ObjectIdentifier);
	});

	it.each([1.5, Number.NaN, Number.POSITIVE_INFINITY])('rejects noninteger ASN.1 values: %s', (value) => {
		expect(() => new asn.Integer({ value })).toThrow(RangeError);
	});

	it('rejects a UTCTime outside its representable year instead of wrapping it', () => {
		expect(() => new asn.UTCTime({ valueDate: new Date('2050-01-01T00:00:00.000Z') })).toThrow(RangeError);
	});

	it.each([Uint8Array.of(0x1e, 1, 0), Uint8Array.of(0x1c, 3, 0, 0, 0)])(
		'rejects incomplete wide string encodings without a decoder exception', (bytes) => {
			expect(asn.fromBER(bytes).offset).toBe(-1);
		},
	);
});

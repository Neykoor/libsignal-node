import { PreKeyError } from './errors.js';
const MIN_REGISTRATION_ID = 1;
const MAX_REGISTRATION_ID = 0x3fff;
const IDENTITY_KEY_LENGTH = 33;
const PUBLIC_KEY_LENGTH = 33;
const SIGNATURE_LENGTH = 64;
const MAX_KEY_ID = 0xffffff;
function isNonNegativeInteger(n) {
    return typeof n === 'number' && Number.isInteger(n) && n >= 0;
}
function assertBufferLength(value, length, field) {
    if (!(value instanceof Uint8Array)) {
        throw new PreKeyError(`${field} must be a Uint8Array`);
    }
    if (value.byteLength !== length) {
        throw new PreKeyError(`${field} has invalid length: expected ${length}, got ${value.byteLength}`);
    }
}
function assertKeyId(value, field) {
    if (!isNonNegativeInteger(value) || value > MAX_KEY_ID) {
        throw new PreKeyError(`${field} is out of range: ${String(value)}`);
    }
}
export function assertValidDeviceKeyBundle(bundle) {
    if (!bundle || typeof bundle !== 'object') {
        throw new PreKeyError('Device key bundle must be an object');
    }
    if (!isNonNegativeInteger(bundle.registrationId) ||
        bundle.registrationId < MIN_REGISTRATION_ID ||
        bundle.registrationId > MAX_REGISTRATION_ID) {
        throw new PreKeyError(`Invalid registrationId: ${String(bundle.registrationId)}`);
    }
    assertBufferLength(bundle.identityKey, IDENTITY_KEY_LENGTH, 'identityKey');
    if (!bundle.signedPreKey || typeof bundle.signedPreKey !== 'object') {
        throw new PreKeyError('Missing signedPreKey');
    }
    assertKeyId(bundle.signedPreKey.keyId, 'signedPreKey.keyId');
    assertBufferLength(bundle.signedPreKey.publicKey, PUBLIC_KEY_LENGTH, 'signedPreKey.publicKey');
    assertBufferLength(bundle.signedPreKey.signature, SIGNATURE_LENGTH, 'signedPreKey.signature');
    if (bundle.preKey) {
        assertKeyId(bundle.preKey.keyId, 'preKey.keyId');
        assertBufferLength(bundle.preKey.publicKey, PUBLIC_KEY_LENGTH, 'preKey.publicKey');
    }
}

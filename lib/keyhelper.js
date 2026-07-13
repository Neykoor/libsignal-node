import * as nodeCrypto from 'crypto';
import * as curve from './curve.js';
function isNonNegativeInteger(n) {
    return typeof n === 'number' && n % 1 === 0 && n >= 0;
}
export const DEFAULT_SIGNED_PRE_KEY_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
export function shouldRotateSignedPreKey(createdAt, maxAgeMs = DEFAULT_SIGNED_PRE_KEY_MAX_AGE_MS) {
    if (!isNonNegativeInteger(createdAt)) {
        throw new TypeError('Invalid argument for createdAt: ' + createdAt);
    }
    if (!isNonNegativeInteger(maxAgeMs)) {
        throw new TypeError('Invalid argument for maxAgeMs: ' + maxAgeMs);
    }
    return Date.now() - createdAt >= maxAgeMs;
}
export const generateIdentityKeyPair = curve.generateKeyPair;
export function generateRegistrationId() {
    let registrationId;
    do {
        registrationId = nodeCrypto.randomBytes(2).readUInt16BE(0) & 0x3fff;
    } while (registrationId === 0);
    return registrationId;
}
export function generateSignedPreKey(identityKeyPair, signedKeyId) {
    if (!(identityKeyPair.privKey instanceof Buffer) ||
        identityKeyPair.privKey.byteLength !== 32 ||
        !(identityKeyPair.pubKey instanceof Buffer) ||
        identityKeyPair.pubKey.byteLength !== 33) {
        throw new TypeError('Invalid argument for identityKeyPair');
    }
    if (!isNonNegativeInteger(signedKeyId)) {
        throw new TypeError('Invalid argument for signedKeyId: ' + signedKeyId);
    }
    const keyPair = curve.generateKeyPair();
    const sig = curve.calculateSignature(identityKeyPair.privKey, keyPair.pubKey);
    return {
        keyId: signedKeyId,
        keyPair,
        signature: sig,
        createdAt: Date.now()
    };
}
export function generatePreKey(keyId) {
    if (!isNonNegativeInteger(keyId)) {
        throw new TypeError('Invalid argument for keyId: ' + keyId);
    }
    const keyPair = curve.generateKeyPair();
    return {
        keyId,
        keyPair
    };
}

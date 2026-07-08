import * as curve from './curve.js';
import type { KeyPair } from './curve.js';
export interface SignedPreKey {
    keyId: number;
    keyPair: KeyPair;
    signature: Buffer;
}
export interface PreKey {
    keyId: number;
    keyPair: KeyPair;
}
export declare const generateIdentityKeyPair: typeof curve.generateKeyPair;
export declare function generateRegistrationId(): number;
export declare function generateSignedPreKey(identityKeyPair: KeyPair, signedKeyId: number): SignedPreKey;
export declare function generatePreKey(keyId: number): PreKey;

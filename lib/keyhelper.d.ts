import * as curve from './curve.js';
import type { KeyPair } from './curve.js';
export interface SignedPreKey {
    keyId: number;
    keyPair: KeyPair;
    signature: Buffer;
    createdAt: number;
}
export interface PreKey {
    keyId: number;
    keyPair: KeyPair;
}
export declare const DEFAULT_SIGNED_PRE_KEY_MAX_AGE_MS: number;
export declare function shouldRotateSignedPreKey(createdAt: number, maxAgeMs?: number): boolean;
export declare const generateIdentityKeyPair: typeof curve.generateKeyPair;
export declare function generateRegistrationId(): number;
export declare function generateSignedPreKey(identityKeyPair: KeyPair, signedKeyId: number): SignedPreKey;
export declare function generatePreKey(keyId: number): PreKey;

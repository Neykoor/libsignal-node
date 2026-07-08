export interface KeyPair {
    pubKey: Buffer;
    privKey: Buffer;
}
export declare function getPublicFromPrivateKey(privKey: Uint8Array): Buffer;
export declare function generateKeyPair(): KeyPair;
export declare function calculateAgreement(pubKeyInput: Uint8Array, privKey: Uint8Array): Buffer;
export declare function calculateSignature(privKey: Uint8Array, message: Uint8Array): Buffer;
export declare function verifySignature(pubKeyInput: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean;

export declare function encrypt(key: Uint8Array, data: Uint8Array, iv: Uint8Array): Buffer;
export declare function decrypt(key: Uint8Array, data: Uint8Array, iv: Uint8Array): Buffer;
export declare function calculateMAC(key: Uint8Array, data: Uint8Array): Buffer;
export declare function hash(data: Uint8Array): Buffer;
export declare function deriveSecrets(input: Uint8Array, salt: Uint8Array, info: Uint8Array, chunks?: number): Buffer[];
export declare function verifyMAC(data: Uint8Array, key: Uint8Array, mac: Uint8Array, length: number): void;

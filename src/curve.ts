import { generateKeyPairSync, diffieHellman } from 'node:crypto';

export interface KeyPair {
    pubKey: Buffer;
    privKey: Buffer;
}

const SPKI_HEADER = Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]);
const PKCS8_HEADER = Buffer.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x12, 0x04, 0x10]);

export function generateKeyPair(): KeyPair {
    const { publicKey, privateKey } = generateKeyPairSync('x25519', {
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });
    return {
        pubKey: publicKey.subarray(SPKI_HEADER.length),
        privKey: privateKey.subarray(PKCS8_HEADER.length)
    };
}

export function calculateAgreement(pubKey: Buffer, privKey: Buffer): Buffer {
    return diffieHellman({
        privateKey: Buffer.concat([PKCS8_HEADER, privKey]),
        publicKey: Buffer.concat([SPKI_HEADER, pubKey])
    });
}

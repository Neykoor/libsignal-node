import { createHash, createHmac, createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export function sha256(data: Buffer): Buffer {
    return createHash('sha256').update(data).digest();
}

export function hmacSha256(key: Buffer, data: Buffer): Buffer {
    return createHmac('sha256', key).update(data).digest();
}

export function hkdf(secret: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
    const prk = createHmac('sha256', salt.length ? salt : Buffer.alloc(32)).update(secret).digest();
    const result = Buffer.alloc(length);
    let current = Buffer.alloc(0);
    let offset = 0;
    let counter = 1;

    while (offset < length) {
        current = createHmac('sha256', prk)
            .update(Buffer.concat([current, info, Buffer.from([counter])]))
            .digest();
        const chunk = Math.min(current.length, length - offset);
        current.copy(result, offset, 0, chunk);
        offset += chunk;
        counter++;
    }

    return result;
}

export function aesEncrypt(plaintext: Buffer, key: Buffer, iv: Buffer): Buffer {
    const cipher = createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

export function aesDecrypt(ciphertext: Buffer, key: Buffer, iv: Buffer): Buffer {
    const decipher = createDecipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function getRandomBytes(length: number): Buffer {
    return randomBytes(length);
}

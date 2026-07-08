export function wipeBuffer(buffer) {
    if (buffer && buffer.byteLength > 0) {
        buffer.fill(0);
    }
}
export function wipeBuffers(...buffers) {
    for (const buffer of buffers) {
        wipeBuffer(buffer);
    }
}

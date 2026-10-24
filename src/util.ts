export function wipeBuffer(buffer: Uint8Array | undefined | null): void {
  if (buffer && buffer.byteLength > 0) {
    buffer.fill(0)
  }
}

export function wipeBuffers(...buffers: Array<Uint8Array | undefined | null>): void {
  for (const buffer of buffers) {
    wipeBuffer(buffer)
  }
}

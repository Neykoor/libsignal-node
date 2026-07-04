export function wipeBuffer(buffer: Buffer | undefined | null): void {
	if (buffer && buffer.byteLength > 0) {
		buffer.fill(0)
	}
}

export function wipeBuffers(...buffers: Array<Buffer | undefined | null>): void {
	for (const buffer of buffers) {
		wipeBuffer(buffer)
	}
}

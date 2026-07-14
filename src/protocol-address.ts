export class ProtocolAddress {
	public id: string
	public deviceId: number

	static from(encodedAddress: string): ProtocolAddress {
		if (typeof encodedAddress !== 'string') {
			throw new Error('Invalid address encoding')
		}

		const sep = encodedAddress.lastIndexOf('.')
		if (sep === -1) {
			throw new Error('Invalid address encoding')
		}

		const id = encodedAddress.slice(0, sep)
		const deviceIdPart = encodedAddress.slice(sep + 1)
		if (!/^\d+$/.test(deviceIdPart)) {
			throw new Error('Invalid address encoding')
		}

		return new ProtocolAddress(id, parseInt(deviceIdPart, 10))
	}

	constructor(id: string, deviceId: number) {
		if (typeof id !== 'string') {
			throw new TypeError('id required for addr')
		}

		if (id.indexOf('.') !== -1) {
			throw new TypeError('encoded addr detected')
		}

		this.id = id

		if (typeof deviceId !== 'number') {
			throw new TypeError('number required for deviceId')
		}

		this.deviceId = deviceId
	}

	toString(): string {
		return `${this.id}.${this.deviceId}`
	}

	is(other: unknown): boolean {
		if (!(other instanceof ProtocolAddress)) {
			return false
		}

		return other.id === this.id && other.deviceId === this.deviceId
	}
}

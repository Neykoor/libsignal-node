import * as $protobuf from 'protobufjs'

export namespace textsecure {
	interface IWhisperMessage {
		ephemeralKey?: Uint8Array | null
		counter?: number | null
		previousCounter?: number | null
		ciphertext?: Uint8Array | null
	}

	class WhisperMessage implements IWhisperMessage {
		constructor(p?: textsecure.IWhisperMessage)
		public ephemeralKey: Uint8Array
		public counter: number
		public previousCounter: number
		public ciphertext: Uint8Array
		public static create(properties?: textsecure.IWhisperMessage): textsecure.WhisperMessage
		public static encode(m: textsecure.IWhisperMessage, w?: $protobuf.Writer): $protobuf.Writer
		public static decode(r: $protobuf.Reader | Uint8Array, l?: number): textsecure.WhisperMessage
		public static fromObject(d: { [k: string]: unknown }): textsecure.WhisperMessage
		public static toObject(m: textsecure.WhisperMessage, o?: $protobuf.IConversionOptions): { [k: string]: unknown }
		public toJSON(): { [k: string]: unknown }
	}

	interface IPreKeyWhisperMessage {
		registrationId?: number | null
		preKeyId?: number | null
		signedPreKeyId?: number | null
		baseKey?: Uint8Array | null
		identityKey?: Uint8Array | null
		message?: Uint8Array | null
	}

	class PreKeyWhisperMessage implements IPreKeyWhisperMessage {
		constructor(p?: textsecure.IPreKeyWhisperMessage)
		public registrationId: number
		public preKeyId: number
		public signedPreKeyId: number
		public baseKey: Uint8Array
		public identityKey: Uint8Array
		public message: Uint8Array
		public static create(properties?: textsecure.IPreKeyWhisperMessage): textsecure.PreKeyWhisperMessage
		public static encode(m: textsecure.IPreKeyWhisperMessage, w?: $protobuf.Writer): $protobuf.Writer
		public static decode(r: $protobuf.Reader | Uint8Array, l?: number): textsecure.PreKeyWhisperMessage
		public static fromObject(d: { [k: string]: unknown }): textsecure.PreKeyWhisperMessage
		public static toObject(
			m: textsecure.PreKeyWhisperMessage,
			o?: $protobuf.IConversionOptions
		): { [k: string]: unknown }
		public toJSON(): { [k: string]: unknown }
	}

	interface IKeyExchangeMessage {
		id?: number | null
		baseKey?: Uint8Array | null
		ephemeralKey?: Uint8Array | null
		identityKey?: Uint8Array | null
		baseKeySignature?: Uint8Array | null
	}

	class KeyExchangeMessage implements IKeyExchangeMessage {
		constructor(p?: textsecure.IKeyExchangeMessage)
		public id: number
		public baseKey: Uint8Array
		public ephemeralKey: Uint8Array
		public identityKey: Uint8Array
		public baseKeySignature: Uint8Array
		public static create(properties?: textsecure.IKeyExchangeMessage): textsecure.KeyExchangeMessage
		public static encode(m: textsecure.IKeyExchangeMessage, w?: $protobuf.Writer): $protobuf.Writer
		public static decode(r: $protobuf.Reader | Uint8Array, l?: number): textsecure.KeyExchangeMessage
		public static fromObject(d: { [k: string]: unknown }): textsecure.KeyExchangeMessage
		public static toObject(
			m: textsecure.KeyExchangeMessage,
			o?: $protobuf.IConversionOptions
		): { [k: string]: unknown }
		public toJSON(): { [k: string]: unknown }
	}
}

declare const $root: { textsecure: typeof textsecure }
export default $root

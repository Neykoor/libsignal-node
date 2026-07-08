declare module 'curve25519-js' {
	export interface Curve25519KeyPair {
		public: Uint8Array
		private: Uint8Array
	}

	export function generateKeyPair(seed: Uint8Array): Curve25519KeyPair
	export function sharedKey(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array
	export function sign(privateKey: Uint8Array, message: Uint8Array, random?: Uint8Array | null): Uint8Array
	export function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean
}

import { BaseKeyType } from './base-key-type'
import type { ChainType } from './chain-type'
import { getLogger } from './logger'

const CLOSED_SESSIONS_MAX = 40
const SESSION_RECORD_VERSION = 'v1'

function assertBuffer(value: unknown): asserts value is Buffer {
	if (!Buffer.isBuffer(value)) {
		throw new TypeError('Buffer required')
	}
}

export interface ChainKey {
	counter: number
	key?: Buffer
}

export interface Chain {
	messageKeys: Record<number, Buffer>
	chainKey: ChainKey
	chainType: ChainType
}

export interface CurrentRatchet {
	ephemeralKeyPair: { pubKey: Buffer; privKey: Buffer }
	lastRemoteEphemeralKey: Buffer
	previousCounter: number
	rootKey: Buffer
}

export interface IndexInfo {
	baseKey: Buffer
	baseKeyType: BaseKeyType
	closed: number
	used: number
	created: number
	remoteIdentityKey: Buffer
}

export interface PendingPreKey {
	signedKeyId: number
	baseKey: Buffer
	preKeyId?: number
}

interface SerializedChain {
	chainKey: { counter: number; key?: string }
	chainType: ChainType
	messageKeys: Record<number, string>
}

export interface SerializedSessionEntry {
	registrationId?: number
	currentRatchet: {
		ephemeralKeyPair: { pubKey: string; privKey: string }
		lastRemoteEphemeralKey: string
		previousCounter: number
		rootKey: string
	}
	indexInfo: {
		baseKey: string
		baseKeyType: BaseKeyType
		closed: number
		used: number
		created: number
		remoteIdentityKey: string
	}
	_chains: Record<string, SerializedChain>
	pendingPreKey?: { signedKeyId: number; baseKey: string; preKeyId?: number }
}

export class SessionEntry {
	public registrationId?: number
	public currentRatchet!: CurrentRatchet
	public indexInfo!: IndexInfo
	public pendingPreKey?: PendingPreKey
	private _chains: Record<string, Chain> = {}

	toString(): string {
		const baseKey = this.indexInfo && this.indexInfo.baseKey && this.indexInfo.baseKey.toString('base64')
		return `<SessionEntry [baseKey=${baseKey}]>`
	}

	inspect(): string {
		return this.toString()
	}

	addChain(key: Buffer, value: Chain): void {
		assertBuffer(key)
		const id = key.toString('base64')
		if (Object.prototype.hasOwnProperty.call(this._chains, id)) {
			throw new Error('Overwrite attempt')
		}

		this._chains[id] = value
	}

	getChain(key: Buffer): Chain | undefined {
		assertBuffer(key)
		return this._chains[key.toString('base64')]
	}

	deleteChain(key: Buffer): void {
		assertBuffer(key)
		const id = key.toString('base64')
		if (!Object.prototype.hasOwnProperty.call(this._chains, id)) {
			throw new ReferenceError('Not Found')
		}

		delete this._chains[id]
	}

	*chains(): IterableIterator<[Buffer, Chain]> {
		for (const [k, v] of Object.entries(this._chains)) {
			yield [Buffer.from(k, 'base64'), v]
		}
	}

	serialize(): SerializedSessionEntry {
		const data: SerializedSessionEntry = {
			registrationId: this.registrationId,
			currentRatchet: {
				ephemeralKeyPair: {
					pubKey: this.currentRatchet.ephemeralKeyPair.pubKey.toString('base64'),
					privKey: this.currentRatchet.ephemeralKeyPair.privKey.toString('base64')
				},
				lastRemoteEphemeralKey: this.currentRatchet.lastRemoteEphemeralKey.toString('base64'),
				previousCounter: this.currentRatchet.previousCounter,
				rootKey: this.currentRatchet.rootKey.toString('base64')
			},
			indexInfo: {
				baseKey: this.indexInfo.baseKey.toString('base64'),
				baseKeyType: this.indexInfo.baseKeyType,
				closed: this.indexInfo.closed,
				used: this.indexInfo.used,
				created: this.indexInfo.created,
				remoteIdentityKey: this.indexInfo.remoteIdentityKey.toString('base64')
			},
			_chains: SessionEntry._serializeChains(this._chains)
		}

		if (this.pendingPreKey) {
			data.pendingPreKey = {
				...this.pendingPreKey,
				baseKey: this.pendingPreKey.baseKey.toString('base64')
			}
		}

		return data
	}

	static deserialize(data: SerializedSessionEntry): SessionEntry {
		const obj = new SessionEntry()
		obj.registrationId = data.registrationId
		obj.currentRatchet = {
			ephemeralKeyPair: {
				pubKey: Buffer.from(data.currentRatchet.ephemeralKeyPair.pubKey, 'base64'),
				privKey: Buffer.from(data.currentRatchet.ephemeralKeyPair.privKey, 'base64')
			},
			lastRemoteEphemeralKey: Buffer.from(data.currentRatchet.lastRemoteEphemeralKey, 'base64'),
			previousCounter: data.currentRatchet.previousCounter,
			rootKey: Buffer.from(data.currentRatchet.rootKey, 'base64')
		}
		obj.indexInfo = {
			baseKey: Buffer.from(data.indexInfo.baseKey, 'base64'),
			baseKeyType: data.indexInfo.baseKeyType,
			closed: data.indexInfo.closed,
			used: data.indexInfo.used,
			created: data.indexInfo.created,
			remoteIdentityKey: Buffer.from(data.indexInfo.remoteIdentityKey, 'base64')
		}
		obj._chains = SessionEntry._deserializeChains(data._chains)

		if (data.pendingPreKey) {
			obj.pendingPreKey = {
				...data.pendingPreKey,
				baseKey: Buffer.from(data.pendingPreKey.baseKey, 'base64')
			}
		}

		return obj
	}

	private static _serializeChains(chains: Record<string, Chain>): Record<string, SerializedChain> {
		const r: Record<string, SerializedChain> = {}

		for (const key of Object.keys(chains)) {
			const c = chains[key]!
			const messageKeys: Record<number, string> = {}
			for (const [idx, mk] of Object.entries(c.messageKeys)) {
				messageKeys[Number(idx)] = mk.toString('base64')
			}

			r[key] = {
				chainKey: {
					counter: c.chainKey.counter,
					key: c.chainKey.key && c.chainKey.key.toString('base64')
				},
				chainType: c.chainType,
				messageKeys
			}
		}

		return r
	}

	private static _deserializeChains(chainsData: Record<string, SerializedChain>): Record<string, Chain> {
		const r: Record<string, Chain> = {}

		for (const key of Object.keys(chainsData)) {
			const c = chainsData[key]!
			const messageKeys: Record<number, Buffer> = {}
			for (const [idx, mk] of Object.entries(c.messageKeys)) {
				messageKeys[Number(idx)] = Buffer.from(mk, 'base64')
			}

			r[key] = {
				chainKey: {
					counter: c.chainKey.counter,
					key: c.chainKey.key ? Buffer.from(c.chainKey.key, 'base64') : undefined
				},
				chainType: c.chainType,
				messageKeys
			}
		}

		return r
	}
}

export interface SerializedSessionRecord {
	version?: string
	registrationId?: number
	_sessions: Record<string, SerializedSessionEntry>
}

interface Migration {
	version: string
	migrate: (data: SerializedSessionRecord) => void
}

const migrations: Migration[] = [
	{
		version: 'v1',
		migrate(data) {
			const sessions = data._sessions
			if (data.registrationId) {
				for (const key in sessions) {
					if (!sessions[key]!.registrationId) {
						sessions[key]!.registrationId = data.registrationId
					}
				}
			} else {
				for (const key in sessions) {
					if (sessions[key]!.indexInfo.closed === -1) {
						getLogger().warn('V1 session storage migration error: missing registrationId for open session', {
							registrationId: data.registrationId,
							version: data.version
						})
					}
				}
			}
		}
	}
]

export class SessionRecord {
	public sessions: Record<string, SessionEntry> = {}
	public version: string = SESSION_RECORD_VERSION

	static createEntry(): SessionEntry {
		return new SessionEntry()
	}

	static migrate(data: SerializedSessionRecord): void {
		let run = data.version === undefined

		for (const migration of migrations) {
			if (run) {
				migration.migrate(data)
			} else if (migration.version === data.version) {
				run = true
			}
		}

		if (!run) {
			throw new Error('Error migrating SessionRecord')
		}
	}

	static deserialize(data: Uint8Array): SessionRecord {
		const parsed: SerializedSessionRecord = JSON.parse(Buffer.from(data).toString('utf-8'))

		if (parsed.version !== SESSION_RECORD_VERSION) {
			SessionRecord.migrate(parsed)
		}

		const obj = new SessionRecord()
		if (parsed._sessions) {
			for (const [key, entry] of Object.entries(parsed._sessions)) {
				obj.sessions[key] = SessionEntry.deserialize(entry)
			}
		}

		return obj
	}

	serialize(): Buffer {
		const _sessions: Record<string, SerializedSessionEntry> = {}
		for (const [key, entry] of Object.entries(this.sessions)) {
			_sessions[key] = entry.serialize()
		}

		return Buffer.from(JSON.stringify({ _sessions, version: this.version }), 'utf-8')
	}

	haveOpenSession(): boolean {
		const openSession = this.getOpenSession()
		return !!openSession && typeof openSession.registrationId === 'number'
	}

	getSession(key: Buffer): SessionEntry | undefined {
		assertBuffer(key)
		const session = this.sessions[key.toString('base64')]
		if (session && session.indexInfo.baseKeyType === BaseKeyType.OURS) {
			throw new Error('Tried to lookup a session using our basekey')
		}

		return session
	}

	getOpenSession(): SessionEntry | undefined {
		for (const session of Object.values(this.sessions)) {
			if (!this.isClosed(session)) {
				return session
			}
		}

		return undefined
	}

	setSession(session: SessionEntry): void {
		this.sessions[session.indexInfo.baseKey.toString('base64')] = session
	}

	getSessions(): SessionEntry[] {
		return Array.from(Object.values(this.sessions)).sort((a, b) => {
			const aUsed = a.indexInfo.used || 0
			const bUsed = b.indexInfo.used || 0
			return aUsed === bUsed ? 0 : aUsed < bUsed ? 1 : -1
		})
	}

	closeSession(session: SessionEntry): void {
		if (this.isClosed(session)) {
			return
		}

		session.indexInfo.closed = Date.now()
	}

	openSession(session: SessionEntry): void {
		session.indexInfo.closed = -1
	}

	isClosed(session: SessionEntry): boolean {
		return session.indexInfo.closed !== -1
	}

	removeOldSessions(): void {
		while (Object.keys(this.sessions).length > CLOSED_SESSIONS_MAX) {
			let oldestKey: string | undefined
			let oldestSession: SessionEntry | undefined

			for (const [key, session] of Object.entries(this.sessions)) {
				if (
					session.indexInfo.closed !== -1 &&
					(!oldestSession || session.indexInfo.closed < oldestSession.indexInfo.closed)
				) {
					oldestKey = key
					oldestSession = session
				}
			}

			if (oldestKey) {
				delete this.sessions[oldestKey]
			} else {
				throw new Error('Corrupt sessions object')
			}
		}
	}

	removeStaleSessions(maxAgeMs: number): void {
		const cutoff = Date.now() - maxAgeMs
		for (const [key, session] of Object.entries(this.sessions)) {
			const lastUsed = session.indexInfo.used || session.indexInfo.created || 0
			if (session.indexInfo.closed !== -1 && lastUsed < cutoff) {
				delete this.sessions[key]
			}
		}
	}

	deleteAllSessions(): void {
		for (const key of Object.keys(this.sessions)) {
			delete this.sessions[key]
		}
	}
									 }
	

import { ProtocolAddress } from './protocol-address.js';
import type { Chain, SessionEntry } from './session-record.js';
import { SessionRecord } from './session-record.js';
import type { EncryptedMessage, SignalStorage } from './types.js';
export declare class SessionCipher {
    private addr;
    private storage;
    private staleSessionMaxAgeMs?;
    constructor(storage: SignalStorage, protocolAddress: ProtocolAddress, staleSessionMaxAgeMs?: number | undefined);
    private _encodeTupleByte;
    private _decodeTupleByte;
    toString(): string;
    getRecord(): Promise<SessionRecord | undefined>;
    storeRecord(record: SessionRecord): Promise<void>;
    queueJob<T>(awaitable: () => Promise<T>): Promise<T>;
    encrypt(data: Uint8Array): Promise<EncryptedMessage>;
    decryptWithSessions(data: Uint8Array, sessions: SessionEntry[]): Promise<{
        session: SessionEntry;
        plaintext: Buffer;
    }>;
    decryptWhisperMessage(data: Uint8Array): Promise<Buffer>;
    decryptPreKeyWhisperMessage(data: Uint8Array): Promise<Buffer>;
    doDecryptWhisperMessage(messageBuffer: Uint8Array, session: SessionEntry): Promise<Buffer>;
    fillMessageKeys(chain: Chain, counter: number): void;
    maybeStepRatchet(session: SessionEntry, remoteKey: Buffer, previousCounter: number): void;
    calculateRatchet(session: SessionEntry, remoteKey: Buffer, sending: boolean): void;
    hasOpenSession(): Promise<boolean>;
    closeOpenSession(): Promise<void>;
}

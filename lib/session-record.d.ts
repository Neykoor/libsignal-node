import { BaseKeyType } from './base-key-type.js';
import type { ChainType } from './chain-type.js';
export interface ChainKey {
    counter: number;
    key?: Buffer;
}
export interface Chain {
    messageKeys: Record<number, Buffer>;
    chainKey: ChainKey;
    chainType: ChainType;
}
export interface CurrentRatchet {
    ephemeralKeyPair: {
        pubKey: Buffer;
        privKey: Buffer;
    };
    lastRemoteEphemeralKey: Buffer;
    previousCounter: number;
    rootKey: Buffer;
}
export interface IndexInfo {
    baseKey: Buffer;
    baseKeyType: BaseKeyType;
    closed: number;
    used: number;
    created: number;
    remoteIdentityKey: Buffer;
}
export interface PendingPreKey {
    signedKeyId: number;
    baseKey: Buffer;
    preKeyId?: number;
}
interface SerializedChain {
    chainKey: {
        counter: number;
        key?: string;
    };
    chainType: ChainType;
    messageKeys: Record<number, string>;
}
export interface SerializedSessionEntry {
    registrationId?: number;
    currentRatchet: {
        ephemeralKeyPair: {
            pubKey: string;
            privKey: string;
        };
        lastRemoteEphemeralKey: string;
        previousCounter: number;
        rootKey: string;
    };
    indexInfo: {
        baseKey: string;
        baseKeyType: BaseKeyType;
        closed: number;
        used: number;
        created: number;
        remoteIdentityKey: string;
    };
    _chains: Record<string, SerializedChain>;
    pendingPreKey?: {
        signedKeyId: number;
        baseKey: string;
        preKeyId?: number;
    };
}
export declare class SessionEntry {
    registrationId?: number;
    currentRatchet: CurrentRatchet;
    indexInfo: IndexInfo;
    pendingPreKey?: PendingPreKey;
    private _chains;
    toString(): string;
    inspect(): string;
    addChain(key: Buffer, value: Chain): void;
    getChain(key: Buffer): Chain | undefined;
    deleteChain(key: Buffer): void;
    chains(): IterableIterator<[Buffer, Chain]>;
    serialize(): SerializedSessionEntry;
    static deserialize(data: SerializedSessionEntry): SessionEntry;
    private static _serializeChains;
    private static _deserializeChains;
}
export interface SerializedSessionRecord {
    version?: string;
    registrationId?: number;
    _sessions: Record<string, SerializedSessionEntry>;
}
export declare class SessionRecord {
    sessions: Record<string, SessionEntry>;
    version: string;
    static createEntry(): SessionEntry;
    static migrate(data: SerializedSessionRecord): void;
    static deserialize(data: Uint8Array): SessionRecord;
    serialize(): Buffer;
    haveOpenSession(): boolean;
    getSession(key: Buffer): SessionEntry | undefined;
    getOpenSession(): SessionEntry | undefined;
    setSession(session: SessionEntry): void;
    getSessions(): SessionEntry[];
    closeSession(session: SessionEntry): void;
    openSession(session: SessionEntry): void;
    isClosed(session: SessionEntry): boolean;
    removeOldSessions(): void;
    removeStaleSessions(maxAgeMs: number): void;
    deleteAllSessions(): void;
}
export {};

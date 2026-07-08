import type { KeyPair } from './curve.js';
import type { Direction } from './direction.js';
import { SessionRecord } from './session-record.js';
import type { SignalStorage } from './types.js';
export declare class MemorySignalStorage implements SignalStorage {
    private identityKeyPair;
    private registrationId;
    private sessions;
    private preKeys;
    private signedPreKeys;
    private trustedIdentities;
    constructor(identityKeyPair: KeyPair, registrationId: number);
    loadSession(id: string): Promise<SessionRecord | undefined>;
    storeSession(id: string, session: SessionRecord): Promise<void>;
    isTrustedIdentity(identifier: string, identityKey: Buffer, _direction: Direction): Promise<boolean>;
    saveIdentity(identifier: string, identityKey: Buffer): Promise<boolean>;
    removeIdentity(identifier: string): Promise<void>;
    loadPreKey(id?: number | string): Promise<KeyPair | undefined>;
    removePreKey(id: number): Promise<void>;
    loadSignedPreKey(id?: number | string): Promise<KeyPair | undefined>;
    getOurRegistrationId(): Promise<number>;
    getOurIdentity(): Promise<KeyPair>;
    storePreKey(id: number, keyPair: KeyPair): void;
    storeSignedPreKey(id: number, keyPair: KeyPair): void;
}

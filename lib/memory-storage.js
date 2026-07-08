import { timingSafeEqual } from 'crypto';
import { SessionRecord } from './session-record.js';
function safeEqual(a, b) {
    if (a.byteLength !== b.byteLength) {
        return false;
    }
    return timingSafeEqual(a, b);
}
export class MemorySignalStorage {
    constructor(identityKeyPair, registrationId) {
        this.sessions = new Map();
        this.preKeys = new Map();
        this.signedPreKeys = new Map();
        this.trustedIdentities = new Map();
        this.identityKeyPair = identityKeyPair;
        this.registrationId = registrationId;
    }
    async loadSession(id) {
        return this.sessions.get(id);
    }
    async storeSession(id, session) {
        this.sessions.set(id, session);
    }
    async isTrustedIdentity(identifier, identityKey, _direction) {
        const existing = this.trustedIdentities.get(identifier);
        if (!existing) {
            this.trustedIdentities.set(identifier, identityKey);
            return true;
        }
        return safeEqual(existing, identityKey);
    }
    async saveIdentity(identifier, identityKey) {
        const existing = this.trustedIdentities.get(identifier);
        this.trustedIdentities.set(identifier, identityKey);
        return !existing || !safeEqual(existing, identityKey);
    }
    async removeIdentity(identifier) {
        this.trustedIdentities.delete(identifier);
        this.sessions.delete(identifier);
    }
    async loadPreKey(id) {
        if (id === undefined) {
            return undefined;
        }
        return this.preKeys.get(Number(id));
    }
    async removePreKey(id) {
        this.preKeys.delete(id);
    }
    async loadSignedPreKey(id) {
        if (id === undefined) {
            return undefined;
        }
        return this.signedPreKeys.get(Number(id));
    }
    async getOurRegistrationId() {
        return this.registrationId;
    }
    async getOurIdentity() {
        return this.identityKeyPair;
    }
    storePreKey(id, keyPair) {
        this.preKeys.set(id, keyPair);
    }
    storeSignedPreKey(id, keyPair) {
        this.signedPreKeys.set(id, keyPair);
    }
}

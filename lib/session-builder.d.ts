import type { ProtocolAddress } from './protocol-address.js';
import { SessionRecord } from './session-record.js';
import type { DeviceKeyBundle, IncomingPreKeyMessage, SignalStorage } from './types.js';
export declare class SessionBuilder {
    private addr;
    private storage;
    constructor(storage: SignalStorage, protocolAddress: ProtocolAddress);
    initOutgoing(device: DeviceKeyBundle): Promise<void>;
    initIncoming(record: SessionRecord, message: IncomingPreKeyMessage): Promise<number | undefined>;
    private initSession;
    private calculateSendingRatchet;
}

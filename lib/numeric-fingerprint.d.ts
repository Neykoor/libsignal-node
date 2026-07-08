export declare class FingerprintGenerator {
    private iterations;
    constructor(iterations: number);
    createFor(localIdentifier: string, localIdentityKey: ArrayBuffer, remoteIdentifier: string, remoteIdentityKey: ArrayBuffer): Promise<string>;
}

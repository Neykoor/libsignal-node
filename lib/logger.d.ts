export interface SignalLogger {
    warn(message: string, meta?: unknown): void;
    debug(message: string, meta?: unknown): void;
}
export declare function setLogger(logger: SignalLogger | null): void;
export declare function getLogger(): SignalLogger;

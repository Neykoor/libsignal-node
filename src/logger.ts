export interface SignalLogger {
	warn(message: string, meta?: unknown): void
	debug(message: string, meta?: unknown): void
}

const noopLogger: SignalLogger = {
	warn(): void {},
	debug(): void {}
}

let currentLogger: SignalLogger = noopLogger

export function setLogger(logger: SignalLogger | null): void {
	currentLogger = logger || noopLogger
}

export function getLogger(): SignalLogger {
	return currentLogger
}

const noopLogger = {
    warn() { },
    debug() { }
};
let currentLogger = noopLogger;
export function setLogger(logger) {
    currentLogger = logger || noopLogger;
}
export function getLogger() {
    return currentLogger;
}

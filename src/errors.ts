export class SignalError extends Error {}

export class UntrustedIdentityKeyError extends SignalError {
  public addr: string
  public identityKey?: Buffer
  public previousIdentityKey?: Buffer

  constructor(addr: string, identityKey?: Buffer, previousIdentityKey?: Buffer) {
    super(`Untrusted identity key for address: ${addr}`)
    this.name = "UntrustedIdentityKeyError"
    this.addr = addr
    this.identityKey = identityKey
    this.previousIdentityKey = previousIdentityKey
  }
}

export class FileSignalStorageLockError extends SignalError {
  public readonly lockPath: string

  constructor(lockPath: string, message: string) {
    super(message)
    this.name = "FileSignalStorageLockError"
    this.lockPath = lockPath
  }
}

export class FileSignalStorageConflictError extends SignalError {
  public readonly filePath: string
  public readonly expectedRevision: number
  public readonly actualRevision: number

  constructor(filePath: string, expectedRevision: number, actualRevision: number, detail?: string) {
    const suffix = detail ? ` (${detail})` : ""
    super(
      `FileSignalStorage conflict for ${filePath}: expected revision ${expectedRevision}, found ${actualRevision}${suffix}. ` +
        "Reload the storage before saving again."
    )
    this.name = "FileSignalStorageConflictError"
    this.filePath = filePath
    this.expectedRevision = expectedRevision
    this.actualRevision = actualRevision
  }
}

export class SessionError extends SignalError {
  constructor(message?: string) {
    super(message)
    this.name = "SessionError"
  }
}

export class MessageCounterError extends SessionError {
  constructor(message?: string) {
    super(message)
    this.name = "MessageCounterError"
  }
}

export class PreKeyError extends SessionError {
  constructor(message?: string) {
    super(message)
    this.name = "PreKeyError"
  }
}

export class SenderKeyError extends SignalError {
  constructor(message?: string) {
    super(message)
    this.name = "SenderKeyError"
  }
}

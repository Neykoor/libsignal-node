import type { ProtocolAddress } from "./protocol-address"

function intValue(num: number): number {
  const MAX_VALUE = 0x7fffffff
  const MIN_VALUE = -0x80000000

  if (num > MAX_VALUE || num < MIN_VALUE) {
    return num & 0xffffffff
  }

  return num
}

function hashCode(str: string): number {
  let hash = 0

  for (let i = 0; i < str.length; i++) {
    hash = intValue(hash * 31 + str.charCodeAt(i))
  }

  return hash
}

export class SenderKeyName {
  private readonly groupId: string
  private readonly sender: ProtocolAddress

  constructor(groupId: string, sender: ProtocolAddress) {
    this.groupId = groupId
    this.sender = sender
  }

  public getGroupId(): string {
    return this.groupId
  }

  public getSender(): ProtocolAddress {
    return this.sender
  }

  public serialize(): string {
    return `${this.groupId}::${this.sender.id}::${this.sender.deviceId}`
  }

  public toString(): string {
    return this.serialize()
  }

  public equals(other: SenderKeyName | null | undefined): boolean {
    if (!other) {
      return false
    }

    return this.groupId === other.groupId && this.sender.is(other.sender)
  }

  public hashCode(): number {
    return hashCode(this.groupId) ^ hashCode(this.sender.toString())
  }
}

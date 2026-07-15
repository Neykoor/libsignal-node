import $protobuf from "protobufjs/minimal.js"

interface IConversionOptions {
  bytes?: typeof String | typeof Array | Function
  defaults?: boolean
}

const $Reader = $protobuf.Reader
const $Writer = $protobuf.Writer
const $util = $protobuf.util

export namespace textsecure {
  export interface IWhisperMessage {
    ephemeralKey?: Uint8Array | null
    counter?: number | null
    previousCounter?: number | null
    ciphertext?: Uint8Array | null
  }

  export class WhisperMessage implements IWhisperMessage {
    ephemeralKey!: Uint8Array
    counter!: number
    previousCounter!: number
    ciphertext!: Uint8Array

    constructor(properties?: IWhisperMessage) {
      if (properties) {
        for (const key of Object.keys(properties) as (keyof IWhisperMessage)[]) {
          const value = properties[key]
          if (value != null) (this as Record<string, unknown>)[key] = value
        }
      }
    }

    static create(properties?: IWhisperMessage): WhisperMessage {
      return new WhisperMessage(properties)
    }

    static encode(message: IWhisperMessage, writer?: InstanceType<typeof $Writer>): InstanceType<typeof $Writer> {
      if (!writer) writer = $Writer.create()
      const own = message as Record<string, unknown>
      if (message.ephemeralKey != null && Object.prototype.hasOwnProperty.call(own, "ephemeralKey"))
        writer.uint32(10).bytes(message.ephemeralKey)
      if (message.counter != null && Object.prototype.hasOwnProperty.call(own, "counter"))
        writer.uint32(16).uint32(message.counter)
      if (message.previousCounter != null && Object.prototype.hasOwnProperty.call(own, "previousCounter"))
        writer.uint32(24).uint32(message.previousCounter)
      if (message.ciphertext != null && Object.prototype.hasOwnProperty.call(own, "ciphertext"))
        writer.uint32(34).bytes(message.ciphertext)
      return writer
    }

    static encodeDelimited(message: IWhisperMessage, writer?: InstanceType<typeof $Writer>): InstanceType<typeof $Writer> {
      return WhisperMessage.encode(message, writer).ldelim()
    }

    static decode(reader: InstanceType<typeof $Reader> | Uint8Array, length?: number): WhisperMessage {
      const r = reader instanceof $Reader ? reader : $Reader.create(reader)
      const end = length === undefined ? r.len : r.pos + length
      const message = new WhisperMessage()
      while (r.pos < end) {
        const tag = r.uint32()
        switch (tag >>> 3) {
          case 1:
            message.ephemeralKey = r.bytes()
            break
          case 2:
            message.counter = r.uint32()
            break
          case 3:
            message.previousCounter = r.uint32()
            break
          case 4:
            message.ciphertext = r.bytes()
            break
          default:
            r.skipType(tag & 7)
            break
        }
      }
      return message
    }

    static decodeDelimited(reader: InstanceType<typeof $Reader> | Uint8Array): WhisperMessage {
      const r = reader instanceof $Reader ? reader : new $Reader(reader)
      return WhisperMessage.decode(r, r.uint32())
    }

    static verify(message: unknown): string | null {
      if (typeof message !== "object" || message === null) return "object expected"
      const m = message as Record<string, unknown>
      if (m.ephemeralKey != null && Object.prototype.hasOwnProperty.call(m, "ephemeralKey"))
        if (!((m.ephemeralKey as Uint8Array)?.length !== undefined || $util.isString(m.ephemeralKey)))
          return "ephemeralKey: buffer expected"
      if (m.counter != null && Object.prototype.hasOwnProperty.call(m, "counter"))
        if (!$util.isInteger(m.counter)) return "counter: integer expected"
      if (m.previousCounter != null && Object.prototype.hasOwnProperty.call(m, "previousCounter"))
        if (!$util.isInteger(m.previousCounter)) return "previousCounter: integer expected"
      if (m.ciphertext != null && Object.prototype.hasOwnProperty.call(m, "ciphertext"))
        if (!((m.ciphertext as Uint8Array)?.length !== undefined || $util.isString(m.ciphertext)))
          return "ciphertext: buffer expected"
      return null
    }

    static fromObject(object: Record<string, unknown>): WhisperMessage {
      if (object instanceof WhisperMessage) return object
      const message = new WhisperMessage()
      if (object.ephemeralKey != null) {
        if (typeof object.ephemeralKey === "string") {
          message.ephemeralKey = $util.newBuffer($util.base64.length(object.ephemeralKey) as unknown as number)
          $util.base64.decode(object.ephemeralKey, message.ephemeralKey, 0)
        } else if ((object.ephemeralKey as Uint8Array).length) {
          message.ephemeralKey = object.ephemeralKey as Uint8Array
        }
      }
      if (object.counter != null) message.counter = (object.counter as number) >>> 0
      if (object.previousCounter != null) message.previousCounter = (object.previousCounter as number) >>> 0
      if (object.ciphertext != null) {
        if (typeof object.ciphertext === "string") {
          message.ciphertext = $util.newBuffer($util.base64.length(object.ciphertext) as unknown as number)
          $util.base64.decode(object.ciphertext, message.ciphertext, 0)
        } else if ((object.ciphertext as Uint8Array).length) {
          message.ciphertext = object.ciphertext as Uint8Array
        }
      }
      return message
    }

    static toObject(message: WhisperMessage, options?: IConversionOptions): Record<string, unknown> {
      const o = options ?? {}
      const object: Record<string, unknown> = {}
      if (o.defaults) {
        object.ephemeralKey = o.bytes === String ? "" : o.bytes === Array ? [] : $util.newBuffer([])
        object.counter = 0
        object.previousCounter = 0
        object.ciphertext = o.bytes === String ? "" : o.bytes === Array ? [] : $util.newBuffer([])
      }
      const m = message as unknown as Record<string, unknown>
      if (message.ephemeralKey != null && Object.prototype.hasOwnProperty.call(m, "ephemeralKey"))
        object.ephemeralKey =
          o.bytes === String
            ? $util.base64.encode(message.ephemeralKey, 0, message.ephemeralKey.length)
            : o.bytes === Array
              ? Array.prototype.slice.call(message.ephemeralKey)
              : message.ephemeralKey
      if (message.counter != null && Object.prototype.hasOwnProperty.call(m, "counter")) object.counter = message.counter
      if (message.previousCounter != null && Object.prototype.hasOwnProperty.call(m, "previousCounter"))
        object.previousCounter = message.previousCounter
      if (message.ciphertext != null && Object.prototype.hasOwnProperty.call(m, "ciphertext"))
        object.ciphertext =
          o.bytes === String
            ? $util.base64.encode(message.ciphertext, 0, message.ciphertext.length)
            : o.bytes === Array
              ? Array.prototype.slice.call(message.ciphertext)
              : message.ciphertext
      return object
    }

    toJSON(): Record<string, unknown> {
      return WhisperMessage.toObject(this, $util.toJSONOptions)
    }
  }
  WhisperMessage.prototype.ephemeralKey = $util.newBuffer([])
  WhisperMessage.prototype.counter = 0
  WhisperMessage.prototype.previousCounter = 0
  WhisperMessage.prototype.ciphertext = $util.newBuffer([])

  export interface IPreKeyWhisperMessage {
    registrationId?: number | null
    preKeyId?: number | null
    signedPreKeyId?: number | null
    baseKey?: Uint8Array | null
    identityKey?: Uint8Array | null
    message?: Uint8Array | null
  }

  export class PreKeyWhisperMessage implements IPreKeyWhisperMessage {
    registrationId!: number
    preKeyId!: number
    signedPreKeyId!: number
    baseKey!: Uint8Array
    identityKey!: Uint8Array
    message!: Uint8Array

    constructor(properties?: IPreKeyWhisperMessage) {
      if (properties) {
        for (const key of Object.keys(properties) as (keyof IPreKeyWhisperMessage)[]) {
          const value = properties[key]
          if (value != null) (this as Record<string, unknown>)[key] = value
        }
      }
    }

    static create(properties?: IPreKeyWhisperMessage): PreKeyWhisperMessage {
      return new PreKeyWhisperMessage(properties)
    }

    static encode(message: IPreKeyWhisperMessage, writer?: InstanceType<typeof $Writer>): InstanceType<typeof $Writer> {
      if (!writer) writer = $Writer.create()
      const own = message as Record<string, unknown>
      if (message.preKeyId != null && Object.prototype.hasOwnProperty.call(own, "preKeyId"))
        writer.uint32(8).uint32(message.preKeyId)
      if (message.baseKey != null && Object.prototype.hasOwnProperty.call(own, "baseKey"))
        writer.uint32(18).bytes(message.baseKey)
      if (message.identityKey != null && Object.prototype.hasOwnProperty.call(own, "identityKey"))
        writer.uint32(26).bytes(message.identityKey)
      if (message.message != null && Object.prototype.hasOwnProperty.call(own, "message"))
        writer.uint32(34).bytes(message.message)
      if (message.registrationId != null && Object.prototype.hasOwnProperty.call(own, "registrationId"))
        writer.uint32(40).uint32(message.registrationId)
      if (message.signedPreKeyId != null && Object.prototype.hasOwnProperty.call(own, "signedPreKeyId"))
        writer.uint32(48).uint32(message.signedPreKeyId)
      return writer
    }

    static encodeDelimited(
      message: IPreKeyWhisperMessage,
      writer?: InstanceType<typeof $Writer>
    ): InstanceType<typeof $Writer> {
      return PreKeyWhisperMessage.encode(message, writer).ldelim()
    }

    static decode(reader: InstanceType<typeof $Reader> | Uint8Array, length?: number): PreKeyWhisperMessage {
      const r = reader instanceof $Reader ? reader : $Reader.create(reader)
      const end = length === undefined ? r.len : r.pos + length
      const message = new PreKeyWhisperMessage()
      while (r.pos < end) {
        const tag = r.uint32()
        switch (tag >>> 3) {
          case 5:
            message.registrationId = r.uint32()
            break
          case 1:
            message.preKeyId = r.uint32()
            break
          case 6:
            message.signedPreKeyId = r.uint32()
            break
          case 2:
            message.baseKey = r.bytes()
            break
          case 3:
            message.identityKey = r.bytes()
            break
          case 4:
            message.message = r.bytes()
            break
          default:
            r.skipType(tag & 7)
            break
        }
      }
      return message
    }

    static decodeDelimited(reader: InstanceType<typeof $Reader> | Uint8Array): PreKeyWhisperMessage {
      const r = reader instanceof $Reader ? reader : new $Reader(reader)
      return PreKeyWhisperMessage.decode(r, r.uint32())
    }

    static verify(message: unknown): string | null {
      if (typeof message !== "object" || message === null) return "object expected"
      const m = message as Record<string, unknown>
      if (m.registrationId != null && Object.prototype.hasOwnProperty.call(m, "registrationId"))
        if (!$util.isInteger(m.registrationId)) return "registrationId: integer expected"
      if (m.preKeyId != null && Object.prototype.hasOwnProperty.call(m, "preKeyId"))
        if (!$util.isInteger(m.preKeyId)) return "preKeyId: integer expected"
      if (m.signedPreKeyId != null && Object.prototype.hasOwnProperty.call(m, "signedPreKeyId"))
        if (!$util.isInteger(m.signedPreKeyId)) return "signedPreKeyId: integer expected"
      if (m.baseKey != null && Object.prototype.hasOwnProperty.call(m, "baseKey"))
        if (!((m.baseKey as Uint8Array)?.length !== undefined || $util.isString(m.baseKey)))
          return "baseKey: buffer expected"
      if (m.identityKey != null && Object.prototype.hasOwnProperty.call(m, "identityKey"))
        if (!((m.identityKey as Uint8Array)?.length !== undefined || $util.isString(m.identityKey)))
          return "identityKey: buffer expected"
      if (m.message != null && Object.prototype.hasOwnProperty.call(m, "message"))
        if (!((m.message as Uint8Array)?.length !== undefined || $util.isString(m.message)))
          return "message: buffer expected"
      return null
    }

    static fromObject(object: Record<string, unknown>): PreKeyWhisperMessage {
      if (object instanceof PreKeyWhisperMessage) return object
      const message = new PreKeyWhisperMessage()
      if (object.registrationId != null) message.registrationId = (object.registrationId as number) >>> 0
      if (object.preKeyId != null) message.preKeyId = (object.preKeyId as number) >>> 0
      if (object.signedPreKeyId != null) message.signedPreKeyId = (object.signedPreKeyId as number) >>> 0
      if (object.baseKey != null) {
        if (typeof object.baseKey === "string") {
          message.baseKey = $util.newBuffer($util.base64.length(object.baseKey) as unknown as number)
          $util.base64.decode(object.baseKey, message.baseKey, 0)
        } else if ((object.baseKey as Uint8Array).length) {
          message.baseKey = object.baseKey as Uint8Array
        }
      }
      if (object.identityKey != null) {
        if (typeof object.identityKey === "string") {
          message.identityKey = $util.newBuffer($util.base64.length(object.identityKey) as unknown as number)
          $util.base64.decode(object.identityKey, message.identityKey, 0)
        } else if ((object.identityKey as Uint8Array).length) {
          message.identityKey = object.identityKey as Uint8Array
        }
      }
      if (object.message != null) {
        if (typeof object.message === "string") {
          message.message = $util.newBuffer($util.base64.length(object.message) as unknown as number)
          $util.base64.decode(object.message, message.message, 0)
        } else if ((object.message as Uint8Array).length) {
          message.message = object.message as Uint8Array
        }
      }
      return message
    }

    static toObject(message: PreKeyWhisperMessage, options?: IConversionOptions): Record<string, unknown> {
      const o = options ?? {}
      const object: Record<string, unknown> = {}
      if (o.defaults) {
        object.preKeyId = 0
        object.baseKey = o.bytes === String ? "" : o.bytes === Array ? [] : $util.newBuffer([])
        object.identityKey = o.bytes === String ? "" : o.bytes === Array ? [] : $util.newBuffer([])
        object.message = o.bytes === String ? "" : o.bytes === Array ? [] : $util.newBuffer([])
        object.registrationId = 0
        object.signedPreKeyId = 0
      }
      const m = message as unknown as Record<string, unknown>
      if (message.preKeyId != null && Object.prototype.hasOwnProperty.call(m, "preKeyId")) object.preKeyId = message.preKeyId
      if (message.baseKey != null && Object.prototype.hasOwnProperty.call(m, "baseKey"))
        object.baseKey =
          o.bytes === String
            ? $util.base64.encode(message.baseKey, 0, message.baseKey.length)
            : o.bytes === Array
              ? Array.prototype.slice.call(message.baseKey)
              : message.baseKey
      if (message.identityKey != null && Object.prototype.hasOwnProperty.call(m, "identityKey"))
        object.identityKey =
          o.bytes === String
            ? $util.base64.encode(message.identityKey, 0, message.identityKey.length)
            : o.bytes === Array
              ? Array.prototype.slice.call(message.identityKey)
              : message.identityKey
      if (message.message != null && Object.prototype.hasOwnProperty.call(m, "message"))
        object.message =
          o.bytes === String
            ? $util.base64.encode(message.message, 0, message.message.length)
            : o.bytes === Array
              ? Array.prototype.slice.call(message.message)
              : message.message
      if (message.registrationId != null && Object.prototype.hasOwnProperty.call(m, "registrationId"))
        object.registrationId = message.registrationId
      if (message.signedPreKeyId != null && Object.prototype.hasOwnProperty.call(m, "signedPreKeyId"))
        object.signedPreKeyId = message.signedPreKeyId
      return object
    }

    toJSON(): Record<string, unknown> {
      return PreKeyWhisperMessage.toObject(this, $util.toJSONOptions)
    }
  }
  PreKeyWhisperMessage.prototype.registrationId = 0
  PreKeyWhisperMessage.prototype.preKeyId = 0
  PreKeyWhisperMessage.prototype.signedPreKeyId = 0
  PreKeyWhisperMessage.prototype.baseKey = $util.newBuffer([])
  PreKeyWhisperMessage.prototype.identityKey = $util.newBuffer([])
  PreKeyWhisperMessage.prototype.message = $util.newBuffer([])

  export interface IKeyExchangeMessage {
    id?: number | null
    baseKey?: Uint8Array | null
    ephemeralKey?: Uint8Array | null
    identityKey?: Uint8Array | null
    baseKeySignature?: Uint8Array | null
  }

  export class KeyExchangeMessage implements IKeyExchangeMessage {
    id!: number
    baseKey!: Uint8Array
    ephemeralKey!: Uint8Array
    identityKey!: Uint8Array
    baseKeySignature!: Uint8Array

    constructor(properties?: IKeyExchangeMessage) {
      if (properties) {
        for (const key of Object.keys(properties) as (keyof IKeyExchangeMessage)[]) {
          const value = properties[key]
          if (value != null) (this as Record<string, unknown>)[key] = value
        }
      }
    }

    static create(properties?: IKeyExchangeMessage): KeyExchangeMessage {
      return new KeyExchangeMessage(properties)
    }

    static encode(message: IKeyExchangeMessage, writer?: InstanceType<typeof $Writer>): InstanceType<typeof $Writer> {
      if (!writer) writer = $Writer.create()
      const own = message as Record<string, unknown>
      if (message.id != null && Object.prototype.hasOwnProperty.call(own, "id")) writer.uint32(8).uint32(message.id)
      if (message.baseKey != null && Object.prototype.hasOwnProperty.call(own, "baseKey"))
        writer.uint32(18).bytes(message.baseKey)
      if (message.ephemeralKey != null && Object.prototype.hasOwnProperty.call(own, "ephemeralKey"))
        writer.uint32(26).bytes(message.ephemeralKey)
      if (message.identityKey != null && Object.prototype.hasOwnProperty.call(own, "identityKey"))
        writer.uint32(34).bytes(message.identityKey)
      if (message.baseKeySignature != null && Object.prototype.hasOwnProperty.call(own, "baseKeySignature"))
        writer.uint32(42).bytes(message.baseKeySignature)
      return writer
    }

    static encodeDelimited(
      message: IKeyExchangeMessage,
      writer?: InstanceType<typeof $Writer>
    ): InstanceType<typeof $Writer> {
      return KeyExchangeMessage.encode(message, writer).ldelim()
    }

    static decode(reader: InstanceType<typeof $Reader> | Uint8Array, length?: number): KeyExchangeMessage {
      const r = reader instanceof $Reader ? reader : $Reader.create(reader)
      const end = length === undefined ? r.len : r.pos + length
      const message = new KeyExchangeMessage()
      while (r.pos < end) {
        const tag = r.uint32()
        switch (tag >>> 3) {
          case 1:
            message.id = r.uint32()
            break
          case 2:
            message.baseKey = r.bytes()
            break
          case 3:
            message.ephemeralKey = r.bytes()
            break
          case 4:
            message.identityKey = r.bytes()
            break
          case 5:
            message.baseKeySignature = r.bytes()
            break
          default:
            r.skipType(tag & 7)
            break
        }
      }
      return message
    }

    static decodeDelimited(reader: InstanceType<typeof $Reader> | Uint8Array): KeyExchangeMessage {
      const r = reader instanceof $Reader ? reader : new $Reader(reader)
      return KeyExchangeMessage.decode(r, r.uint32())
    }

    static verify(message: unknown): string | null {
      if (typeof message !== "object" || message === null) return "object expected"
      const m = message as Record<string, unknown>
      if (m.id != null && Object.prototype.hasOwnProperty.call(m, "id"))
        if (!$util.isInteger(m.id)) return "id: integer expected"
      if (m.baseKey != null && Object.prototype.hasOwnProperty.call(m, "baseKey"))
        if (!((m.baseKey as Uint8Array)?.length !== undefined || $util.isString(m.baseKey)))
          return "baseKey: buffer expected"
      if (m.ephemeralKey != null && Object.prototype.hasOwnProperty.call(m, "ephemeralKey"))
        if (!((m.ephemeralKey as Uint8Array)?.length !== undefined || $util.isString(m.ephemeralKey)))
          return "ephemeralKey: buffer expected"
      if (m.identityKey != null && Object.prototype.hasOwnProperty.call(m, "identityKey"))
        if (!((m.identityKey as Uint8Array)?.length !== undefined || $util.isString(m.identityKey)))
          return "identityKey: buffer expected"
      if (m.baseKeySignature != null && Object.prototype.hasOwnProperty.call(m, "baseKeySignature"))
        if (!((m.baseKeySignature as Uint8Array)?.length !== undefined || $util.isString(m.baseKeySignature)))
          return "baseKeySignature: buffer expected"
      return null
    }

    static fromObject(object: Record<string, unknown>): KeyExchangeMessage {
      if (object instanceof KeyExchangeMessage) return object
      const message = new KeyExchangeMessage()
      if (object.id != null) message.id = (object.id as number) >>> 0
      if (object.baseKey != null) {
        if (typeof object.baseKey === "string") {
          message.baseKey = $util.newBuffer($util.base64.length(object.baseKey) as unknown as number)
          $util.base64.decode(object.baseKey, message.baseKey, 0)
        } else if ((object.baseKey as Uint8Array).length) {
          message.baseKey = object.baseKey as Uint8Array
        }
      }
      if (object.ephemeralKey != null) {
        if (typeof object.ephemeralKey === "string") {
          message.ephemeralKey = $util.newBuffer($util.base64.length(object.ephemeralKey) as unknown as number)
          $util.base64.decode(object.ephemeralKey, message.ephemeralKey, 0)
        } else if ((object.ephemeralKey as Uint8Array).length) {
          message.ephemeralKey = object.ephemeralKey as Uint8Array
        }
      }
      if (object.identityKey != null) {
        if (typeof object.identityKey === "string") {
          message.identityKey = $util.newBuffer($util.base64.length(object.identityKey) as unknown as number)
          $util.base64.decode(object.identityKey, message.identityKey, 0)
        } else if ((object.identityKey as Uint8Array).length) {
          message.identityKey = object.identityKey as Uint8Array
        }
      }
      if (object.baseKeySignature != null) {
        if (typeof object.baseKeySignature === "string") {
          message.baseKeySignature = $util.newBuffer($util.base64.length(object.baseKeySignature) as unknown as number)
          $util.base64.decode(object.baseKeySignature, message.baseKeySignature, 0)
        } else if ((object.baseKeySignature as Uint8Array).length) {
          message.baseKeySignature = object.baseKeySignature as Uint8Array
        }
      }
      return message
    }

    static toObject(message: KeyExchangeMessage, options?: IConversionOptions): Record<string, unknown> {
      const o = options ?? {}
      const object: Record<string, unknown> = {}
      if (o.defaults) {
        object.id = 0
        object.baseKey = o.bytes === String ? "" : o.bytes === Array ? [] : $util.newBuffer([])
        object.ephemeralKey = o.bytes === String ? "" : o.bytes === Array ? [] : $util.newBuffer([])
        object.identityKey = o.bytes === String ? "" : o.bytes === Array ? [] : $util.newBuffer([])
        object.baseKeySignature = o.bytes === String ? "" : o.bytes === Array ? [] : $util.newBuffer([])
      }
      const m = message as unknown as Record<string, unknown>
      if (message.id != null && Object.prototype.hasOwnProperty.call(m, "id")) object.id = message.id
      if (message.baseKey != null && Object.prototype.hasOwnProperty.call(m, "baseKey"))
        object.baseKey =
          o.bytes === String
            ? $util.base64.encode(message.baseKey, 0, message.baseKey.length)
            : o.bytes === Array
              ? Array.prototype.slice.call(message.baseKey)
              : message.baseKey
      if (message.ephemeralKey != null && Object.prototype.hasOwnProperty.call(m, "ephemeralKey"))
        object.ephemeralKey =
          o.bytes === String
            ? $util.base64.encode(message.ephemeralKey, 0, message.ephemeralKey.length)
            : o.bytes === Array
              ? Array.prototype.slice.call(message.ephemeralKey)
              : message.ephemeralKey
      if (message.identityKey != null && Object.prototype.hasOwnProperty.call(m, "identityKey"))
        object.identityKey =
          o.bytes === String
            ? $util.base64.encode(message.identityKey, 0, message.identityKey.length)
            : o.bytes === Array
              ? Array.prototype.slice.call(message.identityKey)
              : message.identityKey
      if (message.baseKeySignature != null && Object.prototype.hasOwnProperty.call(m, "baseKeySignature"))
        object.baseKeySignature =
          o.bytes === String
            ? $util.base64.encode(message.baseKeySignature, 0, message.baseKeySignature.length)
            : o.bytes === Array
              ? Array.prototype.slice.call(message.baseKeySignature)
              : message.baseKeySignature
      return object
    }

    toJSON(): Record<string, unknown> {
      return KeyExchangeMessage.toObject(this, $util.toJSONOptions)
    }
  }
  KeyExchangeMessage.prototype.id = 0
  KeyExchangeMessage.prototype.baseKey = $util.newBuffer([])
  KeyExchangeMessage.prototype.ephemeralKey = $util.newBuffer([])
  KeyExchangeMessage.prototype.identityKey = $util.newBuffer([])
  KeyExchangeMessage.prototype.baseKeySignature = $util.newBuffer([])
}

const $root = { textsecure }
export default $root

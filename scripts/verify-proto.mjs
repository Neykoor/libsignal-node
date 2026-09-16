#!/usr/bin/env node
/**
 * Verifica que `src/whisper-text-protocol.ts` (compilado en lib/) sea byte-compatible
 * con `protos/WhisperTextProtocol.proto`, sin depender de un diff de código generado
 * (que no tendría sentido: pbjs genera un estilo distinto al port a mano).
 *
 * Carga el .proto en tiempo de ejecución con protobufjs (Root.load, ya es dependencia
 * directa del paquete) y hace un round-trip encode/decode con datos aleatorios contra
 * las clases a mano de lib/whisper-text-protocol.js, comparando los bytes producidos.
 *
 * Requiere haber compilado antes: `npm run build && npm run verify:proto`
 */
import { randomBytes } from "node:crypto"
import { fileURLToPath } from "node:url"
import path from "node:path"
import protobuf from "protobufjs"

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const protoPath = path.join(rootDir, "protos", "WhisperTextProtocol.proto")
const libPath = path.join(rootDir, "lib", "whisper-text-protocol.js")

let handWritten
try {
  handWritten = (await import(libPath)).default
} catch (err) {
  console.error(`[verify-proto] No se pudo importar ${libPath}. Corre "npm run build" primero.`)
  console.error(err.message)
  process.exit(1)
}

const root = await protobuf.load(protoPath)

const cases = [
  {
    name: "WhisperMessage",
    typeName: "textsecure.WhisperMessage",
    handWrittenClass: handWritten.textsecure.WhisperMessage,
    sample: {
      ephemeralKey: randomBytes(32),
      counter: 42,
      previousCounter: 7,
      ciphertext: randomBytes(64),
    },
  },
  {
    name: "PreKeyWhisperMessage",
    typeName: "textsecure.PreKeyWhisperMessage",
    handWrittenClass: handWritten.textsecure.PreKeyWhisperMessage,
    sample: {
      registrationId: 12345,
      preKeyId: 7,
      signedPreKeyId: 3,
      baseKey: randomBytes(33),
      identityKey: randomBytes(33),
      message: randomBytes(80),
    },
  },
  {
    name: "KeyExchangeMessage",
    typeName: "textsecure.KeyExchangeMessage",
    handWrittenClass: handWritten.textsecure.KeyExchangeMessage,
    sample: {
      id: 9,
      baseKey: randomBytes(33),
      ephemeralKey: randomBytes(33),
      identityKey: randomBytes(33),
      baseKeySignature: randomBytes(64),
    },
  },
]

let allOk = true

for (const { name, typeName, handWrittenClass, sample: data } of cases) {
  const DynamicType = root.lookupType(typeName)

  // 1) Mismos bytes al codificar el mismo objeto por ambos lados.
  const dynamicBytes = Buffer.from(DynamicType.encode(DynamicType.create(data)).finish())
  const handBytes = Buffer.from(handWrittenClass.encode(data).finish())
  const encodeMatches = dynamicBytes.equals(handBytes)

  // 2) Round-trip cruzado: lo que codifica uno, el otro lo decodifica igual.
  const decodedByHandFromDynamic = handWrittenClass.decode(dynamicBytes)
  const decodedByDynamicFromHand = DynamicType.decode(handBytes)
  const reEncodedByHand = Buffer.from(handWrittenClass.encode(decodedByHandFromDynamic).finish())
  const reEncodedByDynamic = Buffer.from(DynamicType.encode(decodedByDynamicFromHand).finish())
  const roundTripMatches = reEncodedByHand.equals(dynamicBytes) && reEncodedByDynamic.equals(handBytes)

  const ok = encodeMatches && roundTripMatches
  allOk &&= ok

  console.log(`[verify-proto] ${name}: ${ok ? "OK ✅" : "FAIL ❌"}`)
  if (!ok) {
    console.log(`  dynamic: ${dynamicBytes.toString("hex")}`)
    console.log(`  hand:    ${handBytes.toString("hex")}`)
  }
}

if (!allOk) {
  console.error("[verify-proto] whisper-text-protocol.ts NO es byte-compatible con el .proto. Revisa los tags/orden de encode.")
  process.exit(1)
}

console.log("[verify-proto] whisper-text-protocol.ts es byte-compatible con protos/WhisperTextProtocol.proto ✅")

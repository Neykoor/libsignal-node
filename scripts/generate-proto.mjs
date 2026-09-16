#!/usr/bin/env node
/**
 * Equivalente a `generate-proto.sh` de libsignal-node (JS), adaptado a este repo:
 *
 *   yarn pbjs -t static-module -w commonjs -o ./src/WhisperTextProtocol.js ./protos/WhisperTextProtocol.proto
 *
 * En libsignal-node-ts el protobuf está portado a mano en `src/whisper-text-protocol.ts`
 * (ver README, sección "100% TypeScript en src/"), así que este script NO escribe nada
 * dentro de `src/`. Regenera el módulo estático a partir del `.proto` (fuente de verdad)
 * en `generated/`, para poder diffear manualmente contra el port a mano cuando el
 * `.proto` cambie.
 *
 * Para una verificación automática de compatibilidad de bytes, usa `npm run verify:proto`
 * en vez de leer el diff de este generado.
 *
 * Uso: npm run generate:proto
 */
import { execFileSync } from "node:child_process"
import { mkdirSync } from "node:fs"
import { fileURLToPath } from "node:url"
import path from "node:path"

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const protoPath = path.join(rootDir, "protos", "WhisperTextProtocol.proto")
const outDir = path.join(rootDir, "generated")
const outJs = path.join(outDir, "whisper-text-protocol.reference.js")
const outDts = path.join(outDir, "whisper-text-protocol.reference.d.ts")

mkdirSync(outDir, { recursive: true })

const pbjsBin = path.join(rootDir, "node_modules", ".bin", process.platform === "win32" ? "pbjs.cmd" : "pbjs")
const pbtsBin = path.join(rootDir, "node_modules", ".bin", process.platform === "win32" ? "pbts.cmd" : "pbts")

console.log(`[generate-proto] ${protoPath} -> ${outJs}`)
execFileSync(pbjsBin, ["-t", "static-module", "-w", "es6", "-o", outJs, protoPath], { stdio: "inherit" })

console.log(`[generate-proto] ${outJs} -> ${outDts}`)
execFileSync(pbtsBin, ["-o", outDts, outJs], { stdio: "inherit" })

console.log("[generate-proto] listo. 'generated/' es solo referencia, no se usa en el build ni se publica.")

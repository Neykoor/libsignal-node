<div align="center">

<img src="./assets/banner.png" alt="libsignal-node-ts banner" width="100%" />

# libsignal-node-ts

**Port 100% TypeScript de `libsignal-node`, compatible con [BaileysX](https://github.com/Neykoor/BaileysX)**

[![npm](https://img.shields.io/badge/npm-libsignal--node--ts-CB3837?logo=npm&logoColor=white)](https://www.npmjs.com/package/libsignal-node-ts)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![ESM](https://img.shields.io/badge/Module-ESM-yellow)](https://nodejs.org/api/esm.html)
[![Node](https://img.shields.io/badge/Node-%3E%3D20-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License](https://img.shields.io/badge/License-MIT-blue)](./LICENSE)
[![Status](https://img.shields.io/badge/Estado-Estable-success)]()

</div>

---

## ✨ ¿Qué es esto?

`libsignal-node-ts` es una reescritura completa en **TypeScript** de la librería [`libsignal-node`](https://github.com/this-xys/libsignal-node) (Signal Protocol / Double Ratchet), pensada como **reemplazo directo** de la dependencia `libsignal` que usa BaileysX.

Mismo API, misma criptografía, cero `@ts-ignore`, tipado de punta a punta.

## 🚀 Características

- 🔒 Implementación completa del **Double Ratchet** (X3DH, sesiones, ratcheting)
- 📦 Tipado estricto (`strict: true`, `noUncheckedIndexedAccess`)
- ⚡ ESM nativo
- 🔁 API idéntica a `libsignal-node` — `ProtocolAddress`, `SessionBuilder`, `SessionCipher`, `SessionRecord`
- 🧩 Drop-in: solo cambias el import, no tocas el resto de tu código

## 📦 Instalación

```bash
npm install libsignal-node-ts
```

Dependencias en tiempo de ejecución: `curve25519-js` y `protobufjs` (se instalan solas junto con el paquete).

## 📂 Estructura del código fuente

```
libsignal-node-ts/
├── src/
│   ├── index.ts                     # punto de entrada
│   ├── protocol-address.ts
│   ├── session-builder.ts
│   ├── session-cipher.ts
│   ├── session-record.ts
│   ├── curve.ts
│   ├── curve25519-js.d.ts
│   ├── crypto.ts
│   ├── keyhelper.ts
│   ├── numeric-fingerprint.ts
│   ├── prekey-bundle-validator.ts
│   ├── memory-storage.ts
│   ├── logger.ts
│   ├── errors.ts
│   ├── direction.ts
│   ├── base-key-type.ts
│   ├── chain-type.ts
│   ├── queue-job.ts
│   ├── types.ts
│   ├── protobufs.ts
│   ├── whisper-text-protocol.js     # protobufs generados (ESM)
│   └── whisper-text-protocol.d.ts
├── lib/                              # salida compilada (lo que se publica en npm)
├── package.json
└── tsconfig.json
```

## 🔧 Uso en BaileysX

En `src/Signal/libsignal.ts`, reemplaza:

```ts
// @ts-ignore
import * as libsignal from 'libsignal'
// @ts-ignore
import { PreKeyWhisperMessage } from 'libsignal/lib/protobufs.js'
```

por:

```ts
import * as libsignal from 'libsignal-node-ts'
import { protobufs } from 'libsignal-node-ts'
const { PreKeyWhisperMessage } = protobufs
```

Y en el `package.json` de tu proyecto, quita la dependencia `libsignal` y agrega:

```json
"libsignal-node-ts": "^1.0.0"
```

## 📖 Uso básico

```ts
import { ProtocolAddress, SessionBuilder, SessionCipher, MemorySignalStorage, keyhelper } from 'libsignal-node-ts'

const identityKeyPair = keyhelper.generateIdentityKeyPair()
const registrationId = keyhelper.generateRegistrationId()
const storage = new MemorySignalStorage(identityKeyPair, registrationId)
const addr = new ProtocolAddress('5215512345678', 1)

const builder = new SessionBuilder(storage, addr)
await builder.initOutgoing(deviceBundle)

const cipher = new SessionCipher(storage, addr)
const { type, body } = await cipher.encrypt(Buffer.from('hola mundo'))
```

`storage` debe implementar la interfaz `SignalStorage` exportada desde el paquete (o puedes usar `MemorySignalStorage`, incluida para pruebas rápidas y almacenamiento en memoria).

## 🧪 Compilar desde el código fuente

```bash
npm run build
```

Compila `src/` a `lib/` con `tsc` en modo `strict` y corrige las extensiones `.js` de los imports ESM con `tsc-esm-fix`.

---

<div align="center">
Hecho con ☕ para el ecosistema <b>Eris-MD</b> / <b>BaileysX</b>
</div>

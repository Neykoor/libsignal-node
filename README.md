<div align="center">

<!-- Reemplaza esta línea con tu imagen/banner -->
<img src="./assets/banner.png" alt="libsignal-node-ts banner" width="100%" />

# libsignal-node-ts

**Port 100% TypeScript de `libsignal-node`, compatible con [BaileysX](https://github.com/Neykoor/BaileysX)**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![ESM](https://img.shields.io/badge/Module-ESM-yellow)](https://nodejs.org/api/esm.html)
[![License](https://img.shields.io/badge/License-GPL--3.0-blue)](./LICENSE)
[![Status](https://img.shields.io/badge/Estado-Estable-success)]()

</div>

---

## ✨ ¿Qué es esto?

`libsignal-node-ts` es una reescritura completa en **TypeScript** de la librería [`libsignal-node`](https://github.com/this-xys/libsignal-node) (Signal Protocol / Double Ratchet), pensada como **reemplazo directo** de la dependencia `libsignal` que usa BaileysX.

Mismo API, misma criptografía, cero `@ts-ignore`, tipado de punta a punta.

## 🚀 Características

- 🔒 Implementación completa del **Double Ratchet** (X3DH, sesiones, ratcheting)
- 📦 Tipado estricto (`strict: true`, `noUncheckedIndexedAccess`)
- ⚡ ESM nativo, mismo `tsconfig` que BaileysX
- 🔁 API idéntica a `libsignal-node` — `ProtocolAddress`, `SessionBuilder`, `SessionCipher`, `SessionRecord`
- 🧩 Drop-in: solo cambias el import, no tocas el resto de tu código

## 📂 Estructura

```
libsignal-node/
├── src/
│   ├── index.ts                   # punto de entrada
│   ├── protocol-address.ts
│   ├── session-builder.ts
│   ├── session-cipher.ts
│   ├── session-record.ts
│   ├── curve.ts
│   ├── crypto.ts
│   ├── keyhelper.ts
│   ├── numeric-fingerprint.ts
│   ├── errors.ts
│   ├── base-key-type.ts
│   ├── chain-type.ts
│   ├── queue-job.ts
│   ├── types.ts
│   ├── protobufs.ts
│   ├── whisper-text-protocol.js   # protobufs generados (ESM)
│   └── whisper-text-protocol.d.ts
├── package.json
└── tsconfig.json
```

## 🔧 Instalación en BaileysX

1. Copia la carpeta `src/` dentro de tu proyecto, por ejemplo en:

   ```
   src/Signal/libsignal-node/
   ```

2. En `src/Signal/libsignal.ts`, reemplaza:

   ```ts
   // @ts-ignore
   import * as libsignal from 'libsignal'
   // @ts-ignore
   import { PreKeyWhisperMessage } from 'libsignal/src/protobufs'
   ```

   por:

   ```ts
   import * as libsignal from './libsignal-node'
   import { PreKeyWhisperMessage } from './libsignal-node/protobufs'
   ```

3. Quita la dependencia `libsignal` de tu `package.json` — ya no la necesitas. `curve25519-js` y `protobufjs` siguen siendo las únicas dependencias externas.

## 📖 Uso básico

```ts
import { ProtocolAddress, SessionBuilder, SessionCipher, SessionRecord, keyhelper, curve } from './libsignal-node'

const identityKeyPair = keyhelper.generateIdentityKeyPair()
const registrationId = keyhelper.generateRegistrationId()
const addr = new ProtocolAddress('5215512345678', 1)

const builder = new SessionBuilder(storage, addr)
await builder.initOutgoing(deviceBundle)

const cipher = new SessionCipher(storage, addr)
const { type, body } = await cipher.encrypt(Buffer.from('hola mundo'))
```

`storage` debe implementar la interfaz `SignalStorage` exportada desde `types.ts`.

## 🧪 Verificación de tipos

```bash
npm run build
```

Compila sin errores contra `tsconfig.json` en modo `strict`.

## 📜 Licencia

GPL-3.0, heredada de `libsignal-node` (`this-xys/libsignal-node`).

---

<div align="center">
Hecho con ☕ para el ecosistema <b>Eris-MD</b> / <b>BaileysX</b>
</div>

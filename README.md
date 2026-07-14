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

`libsignal-node-ts` es una reescritura completa en **TypeScript** de la librería [`libsignal-node`](https://github.com/WhiskeySockets/libsignal-node) (Signal Protocol / Double Ratchet), pensada como **reemplazo directo** de la dependencia `libsignal` que usa BaileysX.

Mismo API, misma criptografía, cero `@ts-ignore`, tipado de punta a punta — y varias correcciones de seguridad y memoria que la librería original no tiene.

## 🚀 Características

### Lo que ya tiene `libsignal-node-ts` (y `libsignal-node` original no)

- 🛡️ **Verificación de firma real en `initOutgoing`** — la librería original invoca `curve.verifySignature(..., true)`, y ese cuarto parámetro (`isInit`) hace que la firma del signed prekey **nunca se valide** (`return isInit ? true : curveJs.verify(...)`). En `libsignal-node-ts` se eliminó ese bypass: la firma del signed prekey siempre se verifica de verdad antes de iniciar sesión.
- ✅ **Validador de prekey bundles** (`assertValidDeviceKeyBundle`) — módulo nuevo que revisa longitudes de claves, rangos de `registrationId` y `keyId` antes de aceptar un bundle remoto. La librería original no valida nada de esto, solo confía en la forma del objeto.
- 🧹 **Borrado de material sensible en memoria** (`wipeBuffer` / `wipeBuffers`) — las claves de mensaje, cadenas y secretos intermedios se ponen a cero después de usarse en `encrypt`/`decrypt`. La versión original nunca limpia estos buffers, quedan en memoria hasta que el GC los recoja.
- 🔐 **Comparación de identidades a tiempo constante** — `MemorySignalStorage` usa `timingSafeEqual` para comparar identity keys, evitando ataques de timing. La original no trae ningún storage de referencia.
- 💾 **`MemorySignalStorage` incluida** — implementación lista para usar de `SignalStorage` (sesiones, prekeys, identidades de confianza). En la librería original tienes que escribir tu propio storage desde cero, no traen ninguno.
- 🧾 **Sistema de logging inyectable** (`setLogger` / `getLogger`) — permite conectar tu logger (pino, winston, consola) o silenciar todo. La original usa `console.error` fijo, sin forma de desactivarlo.
- 🏷️ **Tipado estricto de punta a punta** — `strict: true`, `noUncheckedIndexedAccess`, interfaces para `SignalStorage`, `DeviceKeyBundle`, `EncryptedMessage`, etc. La original es JS puro sin ningún `.d.ts` propio para su lógica principal.
- 🟦 **100% TypeScript en `src/`**, incluidos los mensajes protobuf de Signal (`whisper-text-protocol.ts`) — sin un solo `.js` generado a mano.

### Lo que tienen en común

- Implementación completa del **Double Ratchet** (X3DH, sesiones, ratcheting)
- Misma API pública: `ProtocolAddress`, `SessionBuilder`, `SessionCipher`, `SessionRecord`, `keyhelper`, `curve`, `crypto`
- Mismas dependencias en runtime: `curve25519-js` y `protobufjs`
- Soporte nativo de `x25519` vía `node:crypto` con fallback a `curve25519-js`

### Pendiente por traer desde `libsignal-node` (roadmap)

- 📄 **`WhisperTextProtocol.proto` + script de generación** — la original mantiene el `.proto` fuente y un `generate-proto.sh` que regenera el código con `pbjs`. En `libsignal-node-ts` el protobuf está portado a mano en TypeScript; falta el `.proto` como fuente de verdad y un script equivalente para regenerarlo automáticamente.
- 🔁 **Workflows de CI/CD** (`.github/workflows`) — build, lint y publish automático a npm, como los que trae la original.
- 🧹 **Config de ESLint propia** (`.eslintrc.json`) para forzar el mismo estilo en todo el repo.
- 📜 **`SECURITY.md` y `CODE_OF_CONDUCT.md`** — políticas de reporte de vulnerabilidades y de comunidad que la original sí documenta.

## 📦 Instalación

```bash
npm install libsignal-node-ts
```

Dependencias en tiempo de ejecución: `curve25519-js` y `protobufjs` (se instalan solas junto con el paquete).

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

Compila `src/` a `lib/` con `tsc` en modo `strict` y corrige las extensiones `.js` de los imports ESM con `tsc-esm-fix`. Con `allowJs` desactivado en `tsconfig.json`, el build falla si se cuela cualquier archivo `.js` dentro de `src/`.

---

<div align="center">
Hecho con ☕ para el ecosistema <b>Eris-MD</b> / <b>BaileysX</b>
</div>

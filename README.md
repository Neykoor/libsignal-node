<div align="center">

<img src="./assets/banner.png" alt="libsignal-node-ts banner" width="100%" />

# libsignal-node-ts

**Port 100% TypeScript de `libsignal-node`, compatible con [BaileysX](https://github.com/Neykoor/BaileysX)**

[![npm](https://img.shields.io/badge/npm-%40neykoor%2Flibsignal--node-CB3837?logo=npm&logoColor=white)](https://www.npmjs.com/package/@neykoor/libsignal-node)
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
- ✅ **Validación de bundles y mensajes entrantes** (`assertValidDeviceKeyBundle`, `assertValidIncomingPreKeyMessage`) — revisan longitudes de claves, rangos de `registrationId`/`keyId` y campos obligatorios antes de aceptar un bundle o procesar un `PreKeyWhisperMessage`. La librería original no valida nada de esto, solo confía en la forma del objeto.
- 🧹 **Borrado de material sensible en memoria** (`wipeBuffer` / `wipeBuffers`) — las claves de mensaje, cadenas y secretos intermedios se ponen a cero después de usarse en `encrypt`/`decrypt` y durante el handshake X3DH (`sharedSecret`, acuerdos `a1..a4` y chunks no usados). La versión original nunca limpia estos buffers, quedan en memoria hasta que el GC los recoja.
- 🔐 **Comparación de identidades a tiempo constante** — `MemorySignalStorage` y `FileSignalStorage` usan `timingSafeEqual` para comparar identity keys, evitando ataques de timing. La original no trae ningún storage de referencia.
- 💾 **`MemorySignalStorage` y `FileSignalStorage` incluidas** — implementaciones listas para usar de `SignalStorage` (sesiones, prekeys, identidades de confianza) **y** `SenderKeyStore` (sender keys de grupo). `FileSignalStorage` persiste todo a un único archivo JSON en disco, para bots que necesitan sobrevivir reinicios. En la librería original tienes que escribir tu propio storage desde cero, no traen ninguno.
- 🧱 **Persistencia versionada, validada y recuperable** — los archivos de `FileSignalStorage` incluyen `formatVersion` y `revision`; los archivos antiguos se migran automáticamente. Al cargar se validan claves, IDs, sesiones, sender keys y prekeys publicadas. Cada operación usa un lock `${file}.lock` y detecta escritores concurrentes con `FileSignalStorageConflictError`; además se guarda `${file}.bak` y se recupera automáticamente si el snapshot principal queda corrupto.
- 🔁 **Rotación de la clave de cifrado en caliente** — `FileSignalStorage.rotateEncryptionKey()` vuelve a escribir el archivo con una clave nueva, o lo deja en JSON plano pasando `undefined`, sin recrear el storage.
- 🛡️ **Política de identidad explícita y observable** — `identityTrustPolicy: 'tofu'` (por defecto) acepta la primera identidad vista; `'strict'` rechaza identidades desconocidas hasta que llames a `saveIdentity()`. `loadIdentity()`/`listIdentities()` permiten consultar el trust store y `onIdentityChanged` avisa cuando una identidad existente cambia; `UntrustedIdentityKeyError` incluye la clave anterior.
- 🔄 **Rotación de sender key al salir un miembro del grupo** (`GroupSessionBuilder.rotate`) — genera una sender key nueva desde cero y descarta la cadena anterior, para que un miembro que sale del grupo no pueda derivar mensajes futuros a partir del chain key que ya tenía. La original no expone ninguna forma de rotar o invalidar una sender key ya distribuida.
- 🧹 **Limpieza automática de signed prekeys retiradas** — al rotar el signed prekey, `MemorySignalStorage`/`FileSignalStorage` guardan el anterior por un grace period configurable (por defecto 3 días, para no romper prekey messages en tránsito) y luego lo borran solos. La original no borra nunca los signed prekeys viejos, se acumulan indefinidamente.
- 🔒 **Cifrado en reposo para `FileSignalStorage`** — con `encryptionKey` (32 bytes) cada guardado se cifra con AES-256-GCM antes de tocar disco. Sin esto (o con la librería original, que no trae ningún storage) tu identity key privada y todas tus sesiones quedan en JSON plano en el filesystem.
- ⏱️ **Mantenimiento automático de prekeys** (`PreKeyPoolManager.startAutoMaintenance`) — repone prekeys y rota el signed prekey solo, y reacciona al consumo de una prekey para reponer el pool sin esperar al próximo intervalo. La original deja esto completamente en manos de quien la usa.
- 🧩 **Bundles y reserva crash-safe de prekeys** — `PreKeyPoolManager.createBundle()` arma un `DeviceKeyBundle` publicable y, por defecto, reserva la prekey para que no se repita en otro bundle. La reserva se persiste antes de devolver el bundle; `releasePreKey()` libera una que no se publicó y la clave privada se conserva hasta que llega el mensaje que la consume. Antes de generar y guardar un lote, el rango de IDs se persiste; si el proceso muere a mitad de la escritura, el siguiente lote salta esos IDs en vez de reutilizarlos y sobrescribir claves ya publicadas.
- 🧾 **Sistema de logging inyectable** (`setLogger` / `getLogger`) — permite conectar tu logger (pino, winston, consola) o silenciar todo. La original usa `console.error` fijo, sin forma de desactivarlo.
- 🏷️ **Tipado estricto de punta a punta** — `strict: true`, `noUncheckedIndexedAccess`, interfaces para `SignalStorage`, `DeviceKeyBundle`, `EncryptedMessage`, etc. La original es JS puro sin ningún `.d.ts` propio para su lógica principal.
- 🟦 **100% TypeScript en `src/`**, incluidos los mensajes protobuf de Signal (`whisper-text-protocol.ts`) — sin un solo `.js` generado a mano.
- 📄 **`WhisperTextProtocol.proto` como fuente de verdad** (`protos/`), igual que la original, más dos scripts que la original no tiene:
  - `npm run generate:proto` — equivalente a `generate-proto.sh` (usa `pbjs`/`pbts`), pero escribe a `generated/` en vez de `src/`, para no romper el port a mano.
  - `npm run verify:proto` — carga el `.proto` en runtime con `protobufjs` y hace un round-trip encode/decode contra las clases de `whisper-text-protocol.ts`, comparando bytes. Es la forma real de detectar si el port a mano se desincroniza del `.proto` (requiere `npm run build` antes).
- 🧹 **Config de ESLint propia** (`.eslintrc.json`) — cubre `src/**/*.ts` (con `@typescript-eslint/recommended`) y `scripts/**/*.mjs`, para forzar el mismo estilo en todo el repo. `no-non-null-assertion` está apagado a propósito: con `noUncheckedIndexedAccess` en `tsconfig.json`, el `!` tras accesos indexados es intencional, no un descuido.

### Lo que tienen en común

- Implementación completa del **Double Ratchet** (X3DH, sesiones, ratcheting)
- Mensajería de **grupo con Sender Key** (`GroupCipher`, `GroupSessionBuilder`, `SenderKeyRecord`, `SenderKeyDistributionMessage`)
- Misma API pública: `ProtocolAddress`, `SessionBuilder`, `SessionCipher`, `SessionRecord`, `GroupCipher`, `GroupSessionBuilder`, `keyhelper`, `curve`, `crypto`
- Misma base criptográfica que `libsignal-node` (curve25519 y `protobufjs`), aquí vía `@neykoor/curve25519-ts`
- Soporte nativo de `x25519` vía `node:crypto` con fallback a `@neykoor/curve25519-ts`

## 📦 Instalación

```bash
npm install @neykoor/libsignal-node
```

Dependencias en tiempo de ejecución: `@neykoor/curve25519-ts`, `pino` y `protobufjs` (se instalan solas junto con el paquete).

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
import * as libsignal from '@neykoor/libsignal-node'
import { protobufs } from '@neykoor/libsignal-node'
const { PreKeyWhisperMessage } = protobufs
```

Y en el `package.json` de tu proyecto, quita la dependencia `libsignal` y agrega:

```json
"@neykoor/libsignal-node": "^1.0.10"
```

## 📖 Uso básico

```ts
import { ProtocolAddress, SessionBuilder, SessionCipher, MemorySignalStorage, keyhelper } from '@neykoor/libsignal-node'

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

## 💾 Storage persistente

Para bots que deben sobrevivir reinicios, usa `FileSignalStorage` en vez de `MemorySignalStorage`:

```ts
import { FileSignalStorage } from '@neykoor/libsignal-node'

const storage = FileSignalStorage.create('./auth/session.json')
```

Si el archivo no existe, genera `identityKeyPair` y `registrationId` nuevos y los guarda; si existe, carga sesiones, prekeys, sender keys, identidades y prekeys publicadas tal cual quedaron. Las escrituras normales se agrupan con debounce; las operaciones críticas (reservar o consumir una prekey, avanzar `nextPreKeyId` y guardar un signed prekey) se persisten de inmediato. Llama a `storage.flush()` (o a `storage.close()`) antes de cerrar el proceso para forzar cualquier escritura pendiente.

El JSON persistido incluye `formatVersion: 1` y un `revision` monotónico. Cada apertura o guardado usa un lock `${file}.lock` para serializar el acceso entre procesos. Si dos instancias cargan el mismo archivo y una guarda primero, la otra recibe `FileSignalStorageConflictError` en vez de sobrescribir cambios ajenos: vuelve a abrir el storage para recargar el estado. Un lock de un proceso que ya no existe se detecta y se elimina automáticamente.

Por defecto se conserva la versión anterior en `${file}.bak` antes de reemplazar el archivo. Si el snapshot principal queda corrupto, `FileSignalStorage.create()` intenta cargar el backup, mueve el archivo dañado a `${file}.corrupt-*` y restaura el backup. Los `.tmp` que hayan quedado de un crash también se limpian al abrir. Puedes desactivar el backup con `backup: false`, ajustar el lock con `lock: false`, `lockTimeoutMs` y `staleLockMs`, y recibir errores de guardados debounced con `onSaveError`:

```ts
const storage = FileSignalStorage.create('./auth/session.json', {
  encryptionKey,
  backup: true,          // ${file}.bak (por defecto)
  lockTimeoutMs: 5000,   // espera máxima por el lock
  staleLockMs: 600000,   // antigüedad para locks de otros hosts
  onSaveError: (error) => console.error('No se pudo guardar', error)
})
```

El JSON persistido valida versión, claves, sesiones, sender keys y prekeys publicadas. Un archivo viejo sin `revision` o sin `publishedPreKeyIds` se carga igual; una versión futura o un snapshot inválido lanza un error indicando el campo exacto en vez de arrancar con estado parcial.

Para cifrar lo que se guarda en disco, pasa una `encryptionKey` de 32 bytes:

```ts
import { randomBytes } from 'crypto'

const encryptionKey = randomBytes(32) // guárdala fuera del código (variable de entorno, secret manager)
const storage = FileSignalStorage.create('./auth/session.json', { encryptionKey })
```

Cada guardado se cifra con AES-256-GCM (IV aleatorio por escritura + auth tag). Si el archivo ya está cifrado y no le das la `encryptionKey` al cargarlo, tira error en vez de fallar en silencio. Para rotar la clave sin recrear el storage:

```ts
storage.rotateEncryptionKey(newEncryptionKey) // reescribe el archivo cifrado con la clave nueva
storage.rotateEncryptionKey(undefined)        // vuelve a JSON plano (no recomendado en producción)
```

La política de identidad es configurable. Por defecto es `tofu` (trust on first use). En modo `strict`, una identidad desconocida se rechaza hasta que la guardes explícitamente:

```ts
const storage = FileSignalStorage.create('./auth/session.json', {
  encryptionKey,
  identityTrustPolicy: 'strict',
  onIdentityChanged: ({ identifier, identityKey, previousIdentityKey }) => {
    console.warn(`La identidad de ${identifier} cambió`, previousIdentityKey, identityKey)
  }
})

// Cuando verifiques la identidad de un contacto por un canal confiable:
// usa el mismo id que pasas a ProtocolAddress (sin el deviceId):
await storage.saveIdentity('5215512345678', remoteIdentityKey)

// Consulta las identidades conocidas:
storage.loadIdentity('5215512345678') // Buffer | undefined (copia defensiva)
storage.listIdentities()              // string[] ordenado
```

`onIdentityChanged` solo se dispara cuando `saveIdentity()` acepta un cambio sobre una identidad que ya existía; el primer trust no cuenta como cambio. Si `isTrustedIdentity()` rechaza una identidad distinta, el error `UntrustedIdentityKeyError` incluye `previousIdentityKey` además de `identityKey` para que puedas mostrar o auditar el cambio.

En `MemorySignalStorage`, las mismas opciones van como cuarto argumento:

```ts
const storage = new MemorySignalStorage(identityKeyPair, registrationId, undefined, {
  identityTrustPolicy: 'strict',
  onIdentityChanged: (event) => console.warn(event)
})
```

## 👥 Mensajería de grupo

```ts
import { GroupSessionBuilder, GroupCipher, SenderKeyName } from '@neykoor/libsignal-node'

const senderKeyName = new SenderKeyName(groupId, addr)
const groupBuilder = new GroupSessionBuilder(storage)
const distributionMessage = await groupBuilder.create(senderKeyName)
// enviar distributionMessage al resto del grupo por sesión 1:1

const groupCipher = new GroupCipher(storage, senderKeyName)
const ciphertext = await groupCipher.encrypt(Buffer.from('hola grupo'))
```

Cuando un miembro sale del grupo, rota tu propia sender key para que no pueda descifrar mensajes futuros:

```ts
const newDistributionMessage = await groupBuilder.rotate(senderKeyName)
// reenviar newDistributionMessage a los miembros que quedan
```

## 🔑 Mantenimiento de prekeys

`PreKeyPoolManager` repone las prekeys y rota el signed prekey cuando hace falta. `startAutoMaintenance()` lo deja corriendo solo:

```ts
import { PreKeyPoolManager } from '@neykoor/libsignal-node'

const poolManager = new PreKeyPoolManager(storage, identityKeyPair)
const stopMaintenance = poolManager.startAutoMaintenance() // revisa cada hora por defecto

process.on('SIGINT', () => {
  stopMaintenance()
  process.exit(0)
})
```

Para publicar un bundle usa `createBundle()`. Toma la `registrationId` del storage y la prekey disponible de menor ID (puedes forzar otra con `preKeyId`):

```ts
const bundle = await poolManager.createBundle()
// bundle.registrationId, bundle.identityKey, bundle.signedPreKey, bundle.preKey

const custom = await poolManager.createBundle({ preKeyId: 42 })

// Si generaste un bundle que finalmente no se publicó:
await poolManager.releasePreKey(bundle.preKey.keyId)

// Para el comportamiento antiguo (sin reservar la prekey):
await poolManager.createBundle({ reserve: false })
```

Por defecto cada bundle **reserva** la prekey elegida, de modo que dos llamadas seguidas devuelven prekeys distintas. La clave privada sigue en el storage para descifrar el `PreKeyWhisperMessage` entrante; recién se elimina cuando el mensaje la consume. La reserva queda persistida, así que un reinicio no vuelve a publicar la misma prekey. Si el storage no implementa `reservePreKey()`, se usa el comportamiento antiguo sin reserva.

`startAutoMaintenance()` también escucha el consumo de prekeys: cuando una prekey se elimina, repone el pool automáticamente si quedó por debajo de `minCount`. La reposición persiste primero el rango de IDs (`nextPreKeyId`) y después genera/escribe las claves. Si el proceso falla a mitad del lote, se pierde ese rango (queda un hueco de IDs), pero nunca se reutiliza un ID que pudo haberse publicado. `getStatus()` informa `preKeyCount`, `availablePreKeyCount` y `publishedPreKeyCount`.

## 🧪 Compilar desde el código fuente

```bash
npm run build
```

Compila `src/` a `lib/` con `tsc` en modo `strict` y corrige las extensiones `.js` de los imports ESM con `tsc-esm-fix`. Con `allowJs` desactivado en `tsconfig.json`, el build falla si se cuela cualquier archivo `.js` dentro de `src/`.

## 🧪 Pruebas e interoperabilidad

```bash
npm test               # compila y ejecuta toda la suite
npm run test:coverage  # cobertura con umbrales mínimos (80% líneas/funciones, 75% ramas)
npm run verify:proto   # round-trip contra protos/WhisperTextProtocol.proto
```

`test/interop.test.mjs` valida la compatibilidad real contra la implementación original [`libsignal`](https://www.npmjs.com/package/libsignal):

- handshake X3DH en ambos sentidos (nuestro iniciador ↔ receptor original y viceversa),
- conversación completa con ratchet y mensajes en ambos sentidos,
- `SessionRecord` serializado por una librería cargado y continuado por la otra,
- bytes de `WhisperMessage` y `PreKeyWhisperMessage` idénticos a los del generador original.

La suite también cubre el hardening de persistencia y prekeys: migración de archivos sin `formatVersion`, rechazo de snapshots corruptos o de versión futura, rotación de la clave de cifrado, lock entre procesos, detección de escritores concurrentes, backups y recuperación automática, limpieza de `.tmp` viejos, política de identidad estricta, `loadIdentity`/`listIdentities`, callbacks de cambio de identidad, `createBundle()` de punta a punta, reserva/release de prekeys, reposición al consumir una prekey y validación de mensajes entrantes malformados.

El workflow de [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) ejecuta lint, tests con cobertura y `verify:proto` en Node 20/22/24 sobre Linux, más Node 24 sobre Windows.

---

<div align="center">
Hecho con ☕ para el ecosistema <b>Eris-MD</b> / <b>BaileysX</b>
</div>

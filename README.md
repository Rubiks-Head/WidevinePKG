# widevine

Pure-Go Widevine CDM (license challenge, license parse, AES-CTR CENC decrypt)
compiled to WebAssembly with a TypeScript wrapper. No binaries, no DLLs.

    node build.mjs   # go -> dist/widevine.wasm + wasm_exec.js, tsc -> dist/index.js

```ts
import { Cdm, Device, Decryptor, decMedia } from "widevine";

const dev = await Device.wvd("device.wvd");
const cdm = await Cdm.open(dev);
await cdm.cert(serviceCert);
const challenge = await cdm.chal(psshB64);
await cdm.upd(licenseBytes);
const media = await decMedia(encryptedMp4, cdm, kid);
```

Device credentials: a `.wvd` file, or `device_client_id_blob` +
`device_private_key` files via `Device.files()`.

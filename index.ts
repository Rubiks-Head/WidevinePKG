import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const dir = path.dirname(fileURLToPath(import.meta.url));

let boot: Promise<void> | null = null;

function load(): Promise<void> {
  if (!boot) {
    boot = (async () => {
      createRequire(import.meta.url)(`${dir}/wasm_exec.js`);
      const go = new (globalThis as any).Go();
      const { instance } = await WebAssembly.instantiate(
        readFileSync(`${dir}/widevine.wasm`),
        go.importObject,
      );
      go.run(instance);
      while (!(globalThis as any).__wvReady) {
        await new Promise((r) => setTimeout(r, 10));
      }
    })();
  }
  return boot;
}

function call(name: string, ...args: unknown[]): Promise<any> {
  return (globalThis as any)[name](...args).then((r: any) => {
    if (!r.ok) {
      const e = new Error(r.error.message) as Error & { code?: string };
      e.code = r.error.code;
      throw e;
    }
    return r.data;
  });
}

export interface CdmCfg {
  wvdPath?: string;
  clientIdPath?: string;
  privateKeyPath?: string;
}

export type KeyProvider = (kid: Buffer) => Buffer | Promise<Buffer>;

export interface CdmLike {
  dec(sample: Buffer, kid: Buffer, iv: Buffer, subs: Buffer): Promise<Buffer>;
}

export class Device {
  private constructor(readonly id: number) {}

  static async wvd(path: string): Promise<Device> {
    await load();
    return new Device(await call("wvLoadWvd", readFileSync(path)));
  }

  static async files(clientIdPath: string, privateKeyPath: string): Promise<Device> {
    await load();
    return new Device(
      await call("wvLoadDev", readFileSync(clientIdPath), readFileSync(privateKeyPath), 1, 3),
    );
  }

  static ok(cfg: CdmCfg): boolean {
    if (cfg.wvdPath) return existsSync(cfg.wvdPath);
    return !!(
      cfg.clientIdPath &&
      cfg.privateKeyPath &&
      existsSync(cfg.clientIdPath) &&
      existsSync(cfg.privateKeyPath)
    );
  }

  static async from(cfg: CdmCfg): Promise<Device | null> {
    if (cfg.wvdPath && existsSync(cfg.wvdPath)) return Device.wvd(cfg.wvdPath);
    if (
      cfg.clientIdPath &&
      cfg.privateKeyPath &&
      existsSync(cfg.clientIdPath) &&
      existsSync(cfg.privateKeyPath)
    ) {
      return Device.files(cfg.clientIdPath, cfg.privateKeyPath);
    }
    return null;
  }
}

export class Cdm implements CdmLike {
  private sid = "";

  private constructor(private dev: Device) {}

  static async open(dev: Device): Promise<Cdm> {
    const c = new Cdm(dev);
    c.sid = await call("wvOpen", dev.id);
    return c;
  }

  async cert(cert: Buffer): Promise<void> {
    await call("wvCert", this.dev.id, this.sid, cert);
  }

  async chal(psshB64: string): Promise<Buffer> {
    return Buffer.from(
      await call("wvChal", this.dev.id, this.sid, Buffer.from(psshB64, "base64")),
    );
  }

  async upd(license: Buffer): Promise<void> {
    await call("wvUpd", this.dev.id, this.sid, license);
  }

  async dec(sample: Buffer, kid: Buffer, iv: Buffer, subs: Buffer): Promise<Buffer> {
    return Buffer.from(await call("wvDec", this.dev.id, this.sid, sample, kid, iv, subs));
  }

  close(): void {
    if (this.sid) call("wvClose", this.dev.id, this.sid).catch(() => {});
    this.sid = "";
  }
}

export class Decryptor implements CdmLike {
  private keys = new Map<string, Buffer>();

  constructor(private keyProvider: KeyProvider) {}

  setKey(kid: Buffer | string, key: Buffer): void {
    this.keys.set(typeof kid === "string" ? kid : kid.toString("hex"), key);
  }

  async dec(sample: Buffer, kid: Buffer, iv: Buffer, subs: Buffer): Promise<Buffer> {
    await load();
    const hex = kid.toString("hex");
    let key = this.keys.get(hex);
    if (!key) {
      key = await this.keyProvider(kid);
      this.keys.set(hex, key);
    }
    return Buffer.from(await call("wvDecRaw", sample, key, iv, subs));
  }
}

function* tops(d: Buffer): Generator<{ type: string; off: number; size: number }> {
  let i = 0;
  while (i + 8 <= d.length) {
    let size = d.readUInt32BE(i);
    const type = d.subarray(i + 4, i + 8).toString("latin1");
    if (size === 1) size = Number(d.readBigUInt64BE(i + 8));
    if (size < 8 || i + size > d.length) break;
    yield { type, off: i, size };
    i += size;
  }
}

function* boxes(d: Buffer, off: number, end: number) {
  let i = off;
  while (i + 8 <= end) {
    let size = d.readUInt32BE(i);
    const type = d.subarray(i + 4, i + 8).toString("latin1");
    if (size === 1) size = Number(d.readBigUInt64BE(i + 8));
    if (size < 8 || i + size > end) break;
    yield { type, off: i, size };
    i += size;
  }
}

export async function decMedia(media: Buffer, cdm: CdmLike, kid: Buffer): Promise<Buffer> {
  const out = Buffer.from(media);
  for (const moof of tops(media)) {
    if (moof.type !== "moof") continue;
    let trun: Buffer | null = null;
    let senc: Buffer | null = null;
    for (const b of boxes(media, moof.off + 8, moof.off + moof.size)) {
      if (b.type !== "traf") continue;
      for (const c of boxes(media, b.off + 8, b.off + b.size)) {
        if (c.type === "trun") trun = media.subarray(c.off + 8, c.off + c.size);
        if (c.type === "senc") senc = media.subarray(c.off + 8, c.off + c.size);
      }
    }
    if (!trun || !senc) continue;
    const flags = trun.readUInt32BE(0) & 0xffffff;
    const cnt = trun.readUInt32BE(4);
    const sizes: number[] = [];
    let i = 8 + (flags & 1 ? 4 : 0) + (flags & 4 ? 4 : 0);
    for (let n = 0; n < cnt; n++) {
      if (flags & 0x100) i += 4;
      if (flags & 0x200) {
        sizes.push(trun.readUInt32BE(i));
        i += 4;
      }
      if (flags & 0x400) i += 4;
      if (flags & 0x800) i += 4;
    }
    const sflags = senc.readUInt32BE(0) & 0xffffff;
    const niv = senc.readUInt32BE(4);
    const ivs: { iv: Buffer; subs: [number, number][] }[] = [];
    i = 8;
    for (let n = 0; n < niv; n++) {
      const iv = Buffer.from(senc.subarray(i, i + 8));
      i += 8;
      const subs: [number, number][] = [];
      if (sflags & 2) {
        const nsub = senc.readUInt16BE(i);
        i += 2;
        for (let k = 0; k < nsub; k++) {
          subs.push([senc.readUInt16BE(i), senc.readUInt32BE(i + 2)]);
          i += 6;
        }
      }
      ivs.push({ iv, subs });
    }
    let mdat = -1;
    for (const b of tops(media.subarray(moof.off + moof.size))) {
      if (b.type === "mdat") {
        mdat = moof.off + moof.size + b.off + 8;
        break;
      }
    }
    if (mdat < 0) continue;
    let cur = mdat;
    for (let n = 0; n < sizes.length; n++) {
      const { iv, subs } = ivs[n] ?? { iv: ivs[ivs.length - 1].iv, subs: [] };
      const sample = media.subarray(cur, cur + sizes[n]);
      const table = subs.length ? subs : [[0, sample.length] as [number, number]];
      const subraw = Buffer.alloc(table.length * 8);
      table.forEach(([c, x], k) => {
        subraw.writeUInt32LE(c, k * 8);
        subraw.writeUInt32LE(x, k * 8 + 4);
      });
      const dec = await cdm.dec(sample, kid, Buffer.concat([iv, Buffer.alloc(8)]), subraw);
      dec.copy(out, cur);
      cur += sizes[n];
    }
  }
  return out;
}

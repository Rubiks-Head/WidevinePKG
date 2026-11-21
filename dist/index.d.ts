export interface CdmCfg {
    wvdPath?: string;
    clientIdPath?: string;
    privateKeyPath?: string;
}
export type KeyProvider = (kid: Buffer) => Buffer | Promise<Buffer>;
export interface CdmLike {
    dec(sample: Buffer, kid: Buffer, iv: Buffer, subs: Buffer): Promise<Buffer>;
}
export declare class Device {
    readonly id: number;
    private constructor();
    static wvd(path: string): Promise<Device>;
    static files(clientIdPath: string, privateKeyPath: string): Promise<Device>;
    static ok(cfg: CdmCfg): boolean;
    static from(cfg: CdmCfg): Promise<Device | null>;
}
export declare class Cdm implements CdmLike {
    private dev;
    private sid;
    private constructor();
    static open(dev: Device): Promise<Cdm>;
    cert(cert: Buffer): Promise<void>;
    chal(psshB64: string): Promise<Buffer>;
    upd(license: Buffer): Promise<void>;
    dec(sample: Buffer, kid: Buffer, iv: Buffer, subs: Buffer): Promise<Buffer>;
    close(): void;
}
export declare class Decryptor implements CdmLike {
    private keyProvider;
    private keys;
    constructor(keyProvider: KeyProvider);
    setKey(kid: Buffer | string, key: Buffer): void;
    dec(sample: Buffer, kid: Buffer, iv: Buffer, subs: Buffer): Promise<Buffer>;
}
export declare function decMedia(media: Buffer, cdm: CdmLike, kid: Buffer): Promise<Buffer>;

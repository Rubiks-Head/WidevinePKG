package wv

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"slices"
	"time"
)

const rootCertB64 = "CpwDCAASAQAY3ZSIiwUijgMwggGKAoIBgQC0/jnDZZAD2zwRlwnoaM3yw16b8udNI7EQ24dl39z7nzWgVwNTTPZtNX2meNuzNtI/nECplSZyf7i+Zt/FIZh4FRZoXS9GDkPLioQ5q/uwNYAivjQji6tTW3LsS7VIaVM+R1/9Cf2ndhOPD5LWTN+udqm62SIQqZ1xRdbX4RklhZxTmpfrhNfMqIiCIHAmIP1+QFAn4iWTb7w+cqD6wb0ptE2CXMG0y5xyfrDpihc+GWP8/YJIK7eyM7l97Eu6iR8nuJuISISqGJIOZfXIbBH/azbkdDTKjDOx+biOtOYS4AKYeVJeRTP/Edzrw1O6fGAaET0A+9K3qjD6T15Id1sX3HXvb9IZbdy+f7B4j9yCYEy/5CkGXmmMOROtFCXtGbLynwGCDVZEiMg17B8RsyTgWQ035Ec86kt/lzEcgXyUikx9aBWE/6UI/Rjn5yvkRycSEbgj7FiTPKwS0ohtQT3F/hzcufjUUT4H5QNvpxLoEve1zqaWVT94tGSCUNIzX5ECAwEAARKAA1jx1k0ECXvf1+9dOwI5F/oUNnVKOGeFVxKnFO41FtU9v0KG9mkAds2T9Hyy355EzUzUrgkYU0Qy7OBhG+XaE9NVxd0ay5AeflvG6Q8in76FAv6QMcxrA4S9IsRV+vXyCM1lQVjofSnaBFiC9TdpvPNaV4QXezKHcLKwdpyywxXRESYqI3WZPrl3IjINvBoZwdVlkHZVdA8OaU1fTY8Zr9/WFjGUqJJfT7x6Mfiujq0zt+kw0IwKimyDNfiKgbL+HIisKmbF/73mF9BiC9yKRfewPlrIHkokL2yl4xyIFIPVxe9enz2FRXPia1BSV0z7kmxmdYrWDRuu8+yvUSIDXQouY5OcCwEgqKmELhfKrnPsIht5rvagcizfB0fbiIYwFHghESKIrNdUdPnzJsKlVshWTwApHQh7evuVicPumFSePGuUBRMS9nG5qxPDDJtGCHs9Mmpoyh6ckGLF7RC5HxclzpC5bc3ERvWjYhN0AqdipPpV2d7PouaAdFUGSdUCDA=="

var ErrSession = errors.New("wv: invalid session")

type ctxPair struct{ enc, mac []byte }

type Session struct {
	id   []byte
	cert []byte
	ctx  map[string]ctxPair
	keys map[string][]byte
}

type Cdm struct {
	dev      *Device
	sessions map[string]*Session
}

func New(dev *Device) *Cdm {
	return &Cdm{dev: dev, sessions: map[string]*Session{}}
}

func (c *Cdm) sess(sid string) (*Session, error) {
	s, ok := c.sessions[sid]
	if !ok {
		return nil, ErrSession
	}
	return s, nil
}

func (c *Cdm) Open() string {
	s := &Session{
		id:   make([]byte, 16),
		ctx:  map[string]ctxPair{},
		keys: map[string][]byte{},
	}
	rand.Read(s.id)
	sid := hex.EncodeToString(s.id)
	c.sessions[sid] = s
	return sid
}

func (c *Cdm) Close(sid string) {
	delete(c.sessions, sid)
}

func pubKey(der []byte) (*rsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("wv: cert public key is not rsa")
	}
	return pub, nil
}

func (c *Cdm) Cert(sid string, cert []byte) error {
	s, err := c.sess(sid)
	if err != nil {
		return err
	}
	signed, err := scan(cert)
	if err != nil {
		return err
	}
	raw := get(signed, 1)
	sig := get(signed, 2)
	if raw == nil || sig == nil {
		return errors.New("wv: bad signed certificate")
	}
	rootRaw, err := base64.StdEncoding.DecodeString(rootCertB64)
	if err != nil {
		return err
	}
	rootSigned, err := scan(rootRaw)
	if err != nil {
		return err
	}
	rootCert, err := scan(get(rootSigned, 1).p)
	if err != nil {
		return err
	}
	pub, err := pubKey(get(rootCert, 4).p)
	if err != nil {
		return err
	}
	h := sha1.Sum(raw.p)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, h[:], sig.p); err != nil {
		return errors.New("wv: certificate signature mismatch")
	}
	s.cert = cert
	return nil
}

func certFields(cert []byte) ([]field, error) {
	signed, err := scan(cert)
	if err != nil {
		return nil, err
	}
	return scan(get(signed, 1).p)
}

func (c *Cdm) encClientID(cert []byte) ([]byte, error) {
	dc, err := certFields(cert)
	if err != nil {
		return nil, err
	}
	privacyKey := make([]byte, 16)
	privacyIV := make([]byte, 16)
	rand.Read(privacyKey)
	rand.Read(privacyIV)
	block, err := aes.NewCipher(privacyKey)
	if err != nil {
		return nil, err
	}
	src := c.dev.ClientID
	pad := 16 - len(src)%16
	src = append(slices.Clone(src), bytes.Repeat([]byte{byte(pad)}, pad)...)
	enc := make([]byte, len(src))
	cipher.NewCBCEncrypter(block, privacyIV).CryptBlocks(enc, src)
	pub, err := pubKey(get(dc, 4).p)
	if err != nil {
		return nil, err
	}
	encKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, privacyKey, nil)
	if err != nil {
		return nil, err
	}
	var out []byte
	if f := get(dc, 7); f != nil {
		out = putStr(out, 1, string(f.p))
	}
	if f := get(dc, 2); f != nil {
		out = putBytes(out, 2, f.p)
	}
	out = putBytes(out, 3, enc)
	out = putBytes(out, 4, privacyIV)
	out = putBytes(out, 5, encKey)
	return out, nil
}

func initData(pssh []byte) ([]byte, error) {
	if len(pssh) < 8 || string(pssh[4:8]) != "pssh" {
		return pssh, nil
	}
	size := int(binary.BigEndian.Uint32(pssh))
	if size > len(pssh) {
		size = len(pssh)
	}
	i := 8 + 4 + 16
	if pssh[8] == 1 {
		if i+4 > size {
			return nil, errTrunc
		}
		i += 4 + int(binary.BigEndian.Uint32(pssh[i:]))*16
	}
	if i+4 > size {
		return nil, errTrunc
	}
	n := int(binary.BigEndian.Uint32(pssh[i:]))
	i += 4
	if i+n > size {
		return nil, errTrunc
	}
	return pssh[i : i+n], nil
}

func (c *Cdm) Chal(sid string, pssh []byte) ([]byte, error) {
	s, err := c.sess(sid)
	if err != nil {
		return nil, err
	}
	init, err := initData(pssh)
	if err != nil {
		return nil, err
	}
	if len(init) == 0 {
		return nil, errors.New("wv: empty pssh init data")
	}
	reqID := make([]byte, 16)
	rand.Read(reqID)
	if c.dev.Typ == 2 {
		copy(reqID[4:], make([]byte, 12))
	}
	var wvPssh []byte
	wvPssh = putBytes(wvPssh, 1, init)
	wvPssh = putInt(wvPssh, 2, 1)
	wvPssh = putBytes(wvPssh, 3, reqID)
	contentID := putBytes(nil, 1, wvPssh)
	var req []byte
	if s.cert != nil {
		enc, err := c.encClientID(s.cert)
		if err != nil {
			return nil, err
		}
		req = putBytes(req, 8, enc)
	} else {
		req = putBytes(req, 1, c.dev.ClientID)
	}
	req = putBytes(req, 2, contentID)
	req = putInt(req, 3, 1)
	req = putInt(req, 4, uint64(time.Now().Unix()))
	req = putInt(req, 6, 21)
	req = putInt(req, 7, uint64(mrand.Uint32N(0x7fffffff)+1))
	h := sha1.Sum(req)
	sig, err := rsa.SignPSS(rand.Reader, c.dev.Priv, crypto.SHA1, h[:], &rsa.PSSOptions{SaltLength: 20})
	if err != nil {
		return nil, err
	}
	var msg []byte
	msg = putInt(msg, 1, 1)
	msg = putBytes(msg, 2, req)
	msg = putBytes(msg, 3, sig)
	enc, mac := deriveCtx(req)
	s.ctx[hex.EncodeToString(reqID)] = ctxPair{enc, mac}
	return msg, nil
}

func unpad(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	n := int(b[len(b)-1])
	if n < 1 || n > 16 || n > len(b) {
		return b
	}
	for _, p := range b[len(b)-n:] {
		if int(p) != n {
			return b
		}
	}
	return b[:len(b)-n]
}

func (c *Cdm) Upd(sid string, lic []byte) error {
	s, err := c.sess(sid)
	if err != nil {
		return err
	}
	msg, err := scan(lic)
	if err != nil {
		return err
	}
	body := get(msg, 2)
	if body == nil || len(body.p) == 0 {
		return errors.New("wv: empty license message")
	}
	if t := get(msg, 1); t != nil && t.v != 2 {
		return fmt.Errorf("wv: expected license message, got type %d", t.v)
	}
	sk := get(msg, 4)
	if sk == nil || len(sk.p) == 0 {
		return errors.New("wv: license missing session key")
	}
	lm, err := scan(body.p)
	if err != nil {
		return err
	}
	var reqID []byte
	if id := get(lm, 1); id != nil {
		if idf, err := scan(id.p); err == nil {
			if r := get(idf, 1); r != nil {
				reqID = r.p
			}
		}
	}
	ctx, ok := s.ctx[hex.EncodeToString(reqID)]
	if !ok {
		return errors.New("wv: no context for license request")
	}
	sessKey, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, c.dev.Priv, sk.p, nil)
	if err != nil {
		return err
	}
	encKey, macSrv, _ := deriveKeys(ctx.enc, ctx.mac, sessKey)
	payload := body.p
	if oem := get(msg, 9); oem != nil {
		payload = append(slices.Clone(oem.p), payload...)
	}
	h := hmac.New(sha256.New, macSrv)
	h.Write(payload)
	if sig := get(msg, 3); sig != nil && !hmac.Equal(h.Sum(nil), sig.p) {
		return errors.New("wv: license signature mismatch")
	}
	for _, kf := range getAll(lm, 3) {
		kc, err := scan(kf.p)
		if err != nil {
			continue
		}
		idf, ivf, keyf := get(kc, 1), get(kc, 2), get(kc, 3)
		if idf == nil || ivf == nil || keyf == nil {
			continue
		}
		block, err := aes.NewCipher(encKey)
		if err != nil {
			return err
		}
		dec := make([]byte, len(keyf.p))
		cipher.NewCBCDecrypter(block, ivf.p).CryptBlocks(dec, keyf.p)
		key := unpad(dec)
		kid := hex.EncodeToString(idf.p)
		s.keys[kid] = key
		if len(idf.p) < 16 {
			pad := make([]byte, 16)
			copy(pad, idf.p)
			s.keys[hex.EncodeToString(pad)] = key
		}
	}
	delete(s.ctx, hex.EncodeToString(reqID))
	return nil
}

func (c *Cdm) Key(sid string, kid []byte) ([]byte, error) {
	s, err := c.sess(sid)
	if err != nil {
		return nil, err
	}
	key, ok := s.keys[hex.EncodeToString(kid)]
	if !ok {
		return nil, fmt.Errorf("wv: no key for kid %x", kid)
	}
	return key, nil
}

func (c *Cdm) Dec(sid string, sample, kid, iv, subs []byte) ([]byte, error) {
	key, err := c.Key(sid, kid)
	if err != nil {
		return nil, err
	}
	return Decrypt(sample, key, iv, subs)
}

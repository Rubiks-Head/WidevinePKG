package wv

import (
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha256"
)

func ecb(key, data []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, len(data))
	for i := 0; i+16 <= len(data); i += 16 {
		c.Encrypt(out[i:i+16], data[i:i+16])
	}
	return out
}

func dbl(block []byte) []byte {
	out := make([]byte, 16)
	carry := byte(0)
	for i := 15; i >= 0; i-- {
		out[i] = block[i]<<1 | carry
		carry = 0
		if block[i]&0x80 != 0 {
			carry = 1
		}
	}
	if carry != 0 {
		out[15] ^= 0x87
	}
	return out
}

func cmac(key, msg []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil || len(key) != 16 {
		return nil
	}
	l := make([]byte, 16)
	c.Encrypt(l, make([]byte, 16))
	k1 := dbl(l)
	k2 := dbl(k1)
	n := (len(msg) + 15) / 16
	if n == 0 {
		n = 1
	}
	padded := make([]byte, n*16)
	copy(padded, msg)
	last := (n - 1) * 16
	sub := k1
	if len(msg) == 0 || len(msg)%16 != 0 {
		padded[len(msg)] = 0x80
		sub = k2
	}
	for i := 0; i < 16; i++ {
		padded[last+i] ^= sub[i]
	}
	x := make([]byte, 16)
	y := make([]byte, 16)
	for i := 0; i < n; i++ {
		for j := 0; j < 16; j++ {
			y[j] = x[j] ^ padded[i*16+j]
		}
		c.Encrypt(x, y)
	}
	return x
}

func deriveCtx(msg []byte) (enc, mac []byte) {
	sz := make([]byte, 4)
	sz[3] = 128
	enc = append(append(append([]byte("ENCRYPTION"), 0), msg...), sz...)
	sz = make([]byte, 4)
	sz[2] = 2
	mac = append(append(append([]byte("AUTHENTICATION"), 0), msg...), sz...)
	return enc, mac
}

func derive(ctx, key []byte, counter byte) []byte {
	return cmac(key, append([]byte{counter}, ctx...))
}

func deriveKeys(encCtx, macCtx, key []byte) (encKey, macSrv, macCli []byte) {
	encKey = derive(encCtx, key, 1)
	macSrv = append(derive(macCtx, key, 1), derive(macCtx, key, 2)...)
	macCli = append(derive(macCtx, key, 3), derive(macCtx, key, 4)...)
	return encKey, macSrv, macCli
}

func sha1sum(b []byte) []byte {
	h := sha1.Sum(b)
	return h[:]
}

func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

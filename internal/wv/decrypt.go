package wv

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"slices"
)

func Decrypt(data, key, iv, subs []byte) ([]byte, error) {
	if len(iv) != 16 {
		return nil, errors.New("wv: iv must be 16 bytes")
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := slices.Clone(data)
	pos := 0
	for i := 0; i+8 <= len(subs); i += 8 {
		clear := int(binary.LittleEndian.Uint32(subs[i:]))
		crypt := int(binary.LittleEndian.Uint32(subs[i+4:]))
		pos += clear
		for crypt > 0 {
			if pos >= len(data) {
				return out, nil
			}
			off := pos % 16
			n := min(crypt, 16-off)
			if pos+n > len(data) {
				n = len(data) - pos
			}
			var ctr [16]byte
			copy(ctr[:], iv)
			addBE(&ctr, pos/16)
			var ks [16]byte
			c.Encrypt(ks[:], ctr[:])
			for j := 0; j < n; j++ {
				out[pos+j] = data[pos+j] ^ ks[off+j]
			}
			pos += n
			crypt -= n
		}
	}
	return out, nil
}

func addBE(ctr *[16]byte, n int) {
	for i := 15; i >= 0 && n > 0; i-- {
		sum := int(ctr[i]) + (n & 0xff)
		ctr[i] = byte(sum)
		n = (n >> 8) + (sum >> 8)
	}
}

package wv

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
)

type Device struct {
	Typ      int
	Level    int
	Priv     *rsa.PrivateKey
	PrivDer  []byte
	ClientID []byte
	SystemID uint32
}

func parseKey(der []byte) (*rsa.PrivateKey, error) {
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("wv: bad private key der")
	}
	priv, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("wv: private key is not rsa")
	}
	return priv, nil
}

func drmCert(clientID []byte) ([]field, error) {
	ci, err := scan(clientID)
	if err != nil {
		return nil, err
	}
	tok := get(ci, 2)
	if tok == nil {
		return nil, errors.New("wv: client id missing token")
	}
	signed, err := scan(tok.p)
	if err != nil {
		return nil, err
	}
	raw := get(signed, 1)
	if raw == nil {
		return nil, errors.New("wv: signed cert missing certificate")
	}
	return scan(raw.p)
}

func NewDevice(clientID, privDer []byte, typ, level int) (*Device, error) {
	priv, err := parseKey(privDer)
	if err != nil {
		return nil, err
	}
	d := &Device{Typ: typ, Level: level, Priv: priv, PrivDer: privDer, ClientID: clientID}
	if dc, err := drmCert(clientID); err == nil {
		if sys := get(dc, 5); sys != nil {
			d.SystemID = uint32(sys.v)
		}
	}
	return d, nil
}

func LoadWvd(b []byte) (*Device, error) {
	if len(b) < 8 || string(b[:3]) != "WVD" {
		return nil, errors.New("wv: bad wvd magic")
	}
	ver := b[3]
	if ver < 1 || ver > 2 {
		return nil, fmt.Errorf("wv: unsupported wvd version %d", ver)
	}
	typ, level := int(b[4]), int(b[5])
	i := 7
	if i+2 > len(b) {
		return nil, errTrunc
	}
	pkLen := int(binary.BigEndian.Uint16(b[i:]))
	i += 2
	if i+pkLen+2 > len(b) {
		return nil, errTrunc
	}
	privDer := b[i : i+pkLen]
	i += pkLen
	ciLen := int(binary.BigEndian.Uint16(b[i:]))
	i += 2
	if i+ciLen > len(b) {
		return nil, errTrunc
	}
	clientID := append([]byte(nil), b[i:i+ciLen]...)
	i += ciLen
	if ver == 1 && i+2 <= len(b) {
		vmpLen := int(binary.BigEndian.Uint16(b[i:]))
		i += 2
		if i+vmpLen <= len(b) && vmpLen > 0 {
			clientID = putBytes(clientID, 7, b[i:i+vmpLen])
		}
	}
	return NewDevice(clientID, privDer, typ, level)
}

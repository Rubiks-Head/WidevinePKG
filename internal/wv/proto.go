package wv

import (
	"encoding/binary"
	"errors"
)

var errTrunc = errors.New("wv: truncated message")
var errWire = errors.New("wv: bad wire type")

func putVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func putTag(b []byte, num, wt int) []byte {
	return putVarint(b, uint64(num<<3|wt))
}

func putInt(b []byte, num int, v uint64) []byte {
	return putVarint(putTag(b, num, 0), v)
}

func putStr(b []byte, num int, s string) []byte {
	return putBytes(b, num, []byte(s))
}

func putBytes(b []byte, num int, p []byte) []byte {
	b = putTag(b, num, 2)
	b = putVarint(b, uint64(len(p)))
	return append(b, p...)
}

type field struct {
	num int
	wt  int
	v   uint64
	p   []byte
}

func scan(b []byte) ([]field, error) {
	var fs []field
	for i := 0; i < len(b); {
		t, n := binary.Uvarint(b[i:])
		if n <= 0 {
			return nil, errTrunc
		}
		i += n
		f := field{num: int(t >> 3), wt: int(t & 7)}
		switch f.wt {
		case 0:
			v, m := binary.Uvarint(b[i:])
			if m <= 0 {
				return nil, errTrunc
			}
			f.v = v
			i += m
		case 1:
			if i+8 > len(b) {
				return nil, errTrunc
			}
			f.p = b[i : i+8]
			i += 8
		case 2:
			l, m := binary.Uvarint(b[i:])
			if m <= 0 {
				return nil, errTrunc
			}
			i += m
			if l > uint64(len(b)-i) {
				return nil, errTrunc
			}
			f.p = b[i : i+int(l)]
			i += int(l)
		case 5:
			if i+4 > len(b) {
				return nil, errTrunc
			}
			f.p = b[i : i+4]
			i += 4
		default:
			return nil, errWire
		}
		fs = append(fs, f)
	}
	return fs, nil
}

func get(fs []field, num int) *field {
	for i := range fs {
		if fs[i].num == num {
			return &fs[i]
		}
	}
	return nil
}

func getAll(fs []field, num int) []*field {
	var out []*field
	for i := range fs {
		if fs[i].num == num {
			out = append(out, &fs[i])
		}
	}
	return out
}

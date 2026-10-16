package nostr

import (
	"errors"
	"strings"
)

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

// Bech32Decode decodes a NIP-19 bech32 string (plain bech32, not bech32m)
// into its prefix and 8-bit payload.
func Bech32Decode(s string) (string, []byte, error) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, errors.New("bech32: mixed case")
	}
	s = strings.ToLower(s)
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, errors.New("bech32: bad separator position")
	}
	hrp := s[:pos]
	var data []byte
	for _, c := range s[pos+1:] {
		i := strings.IndexRune(charset, c)
		if i < 0 {
			return "", nil, errors.New("bech32: invalid character")
		}
		data = append(data, byte(i))
	}
	if polymod(append(hrpExpand(hrp), data...)) != 1 {
		return "", nil, errors.New("bech32: bad checksum")
	}
	out, err := convertBits(data[:len(data)-6], 5, 8, false)
	return hrp, out, err
}

// Bech32Encode encodes an 8-bit payload under hrp.
func Bech32Encode(hrp string, payload []byte) string {
	data, _ := convertBits(payload, 8, 5, true)
	values := append(hrpExpand(hrp), data...)
	pm := polymod(append(values, 0, 0, 0, 0, 0, 0)) ^ 1
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, d := range data {
		b.WriteByte(charset[d])
	}
	for i := 0; i < 6; i++ {
		b.WriteByte(charset[(pm>>uint(5*(5-i)))&31])
	}
	return b.String()
}

func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	acc, bits := uint32(0), uint(0)
	maxv := uint32(1)<<to - 1
	var out []byte
	for _, v := range data {
		acc = acc<<from | uint32(v)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv))
		}
	} else if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, errors.New("bech32: bad padding")
	}
	return out, nil
}

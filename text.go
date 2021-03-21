package md5digest

import (
	"crypto/md5"
	"encoding/base64"
)

const expectTextDataSize = 22

// base64.RawURLEncoding.EncodedLen(md5.Size) == 22

// MarshalText implements the encoding.TextMarshaler interface.
func (d *MD5Digest) MarshalText() (text []byte, err error) {
	enc := base64.RawURLEncoding
	text = make([]byte, expectTextDataSize)
	enc.Encode(text, d.digest[:])
	return
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (d *MD5Digest) UnmarshalText(text []byte) (err error) {
	if dlen := len(text); dlen != expectTextDataSize {
		err = &ErrIncorrectSize{
			ReceivedBufferSize: dlen,
		}
		return
	}
	enc := base64.RawURLEncoding
	n, err := enc.Decode(d.digest[:], text)
	if nil != err {
		return
	}
	if n != md5.Size {
		err = &ErrIncorrectSize{
			ReceivedBufferSize: n,
		}
		return
	}
	return
}

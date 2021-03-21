package md5digest

import (
	"crypto/md5"
	"encoding/base64"
)

// MarshalText implements the encoding.TextMarshaler interface.
func (d *MD5Digest) MarshalText() (text []byte, err error) {
	enc := base64.RawURLEncoding
	text = make([]byte, enc.EncodedLen(md5.Size))
	enc.Encode(text, d.digest[:])
	return
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (d *MD5Digest) UnmarshalText(text []byte) (err error) {
	enc := base64.RawURLEncoding
	dbuf := make([]byte, enc.DecodedLen(len(text)))
	n, err := enc.Decode(dbuf, []byte(text))
	if nil != err {
		return
	}
	if n != md5.Size {
		err = &ErrIncorrectSize{
			ReceivedBufferSize: n,
		}
		return
	}
	copy(d.digest[:], dbuf)
	return
}

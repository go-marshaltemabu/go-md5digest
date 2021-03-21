package md5digest

import (
	"crypto/md5"
)

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (d *MD5Digest) MarshalBinary() (data []byte, err error) {
	data = make([]byte, md5.Size)
	copy(data, d.digest[:])
	return
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (d *MD5Digest) UnmarshalBinary(data []byte) error {
	return d.setDigestWithBytes(data)
}

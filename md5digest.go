package md5digest

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
)

// MD5Digest contain MD5 message digest.
type MD5Digest struct {
	digest [md5.Size]byte
}

// SetDigest set digest given checksum.
func (d *MD5Digest) SetDigest(chksum *[md5.Size]byte) {
	copy(d.digest[:], chksum[:])
}

// SumBytes set digest with given bytes.
func (d *MD5Digest) SumBytes(buf []byte) {
	d.digest = md5.Sum(buf)
}

// SumString set digest with given string.
func (d *MD5Digest) SumString(v string) {
	d.digest = md5.Sum([]byte(v))
}

// Int64s return digest in 2 signed int64.
func (d *MD5Digest) Int64s() (d0, d1 int64) {
	b := d.digest[:]
	d0 = int64(binary.LittleEndian.Uint64(b[0:]))
	d1 = int64(binary.LittleEndian.Uint64(b[8:]))
	return
}

// Uint64s return digest in 2 unsigned int64.
func (d *MD5Digest) Uint64s() (d0, d1 uint64) {
	b := d.digest[:]
	d0 = binary.LittleEndian.Uint64(b[0:])
	d1 = binary.LittleEndian.Uint64(b[8:])
	return
}

// Base64RawURLString return digest in base64url-nopadding encoded string.
func (d *MD5Digest) SetDigestWithBase64RawURLString(s string) (err error) {
	buf, err := base64.RawURLEncoding.DecodeString(s)
	if nil != err {
		return
	}
	if len(buf) != md5.Size {
		err = &ErrIncorrectSize{
			ReceivedBufferSize: len(buf),
		}
		return
	}
	copy(d.digest[:], buf)
	return
}

// Base64RawURLString return digest in base64url-nopadding encoded string.
func (d *MD5Digest) Base64RawURLString() string {
	return base64.RawURLEncoding.EncodeToString(d.digest[:])
}

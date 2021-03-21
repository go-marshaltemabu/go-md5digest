package md5digest

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
)

var emptyDigest [md5.Size]byte

// MD5Digest contain MD5 message digest.
type MD5Digest struct {
	digest [md5.Size]byte
}

// NewMD5DigestWithInt64s create new instance of MD5Digest and initialize with int64s.
func NewMD5DigestWithInt64s(d0, d1 int64) (d MD5Digest) {
	d.SetDigestWithInt64s(d0, d1)
	return
}

// NewMD5DigestWithUint64s create new instance of MD5Digest and initialize with unsigned int64s.
func NewMD5DigestWithUint64s(d0, d1 uint64) (d MD5Digest) {
	d.SetDigestWithUint64s(d0, d1)
	return
}

// NewMD5DigestWithBase64RawURLString create new instance of MD5Digest and initialize with base64url encoded string.
// An empty digest will be return if error occurs on decoding given string.
func NewMD5DigestWithBase64RawURLString(s string) (d MD5Digest) {
	if err := d.SetDigestWithBase64RawURLString(s); nil != err {
		d.digest = emptyDigest
	}
	return
}

// NewMD5DigestWithBase64RawStdString create new instance of MD5Digest and initialize with base64std encoded string.
// An empty digest will be return if error occurs on decoding given string.
func NewMD5DigestWithBase64RawStdString(s string) (d MD5Digest) {
	if err := d.SetDigestWithBase64RawStdString(s); nil != err {
		d.digest = emptyDigest
	}
	return
}

// NewMD5DigestWithHexString create new instance of MD5Digest and initialize with hex encoded string.
// An empty digest will be return if error occurs on decoding given string.
func NewMD5DigestWithHexString(s string) (d MD5Digest) {
	if err := d.SetDigestWithHexString(s); nil != err {
		d.digest = emptyDigest
	}
	return
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

// Clear set digest to zero.
func (d *MD5Digest) Clear() {
	d.digest = emptyDigest
}

// IsEmpty check if digest is zero.
func (d *MD5Digest) IsEmpty() bool {
	return (d.digest == emptyDigest)
}

// Equal check if two digest are the same.
func (d *MD5Digest) Equal(other *MD5Digest) bool {
	return d.digest == other.digest
}

// Int64s return digest in 2 signed int64.
func (d *MD5Digest) Int64s() (d0, d1 int64) {
	b := d.digest[:]
	d0 = int64(binary.LittleEndian.Uint64(b[0:]))
	d1 = int64(binary.LittleEndian.Uint64(b[8:]))
	return
}

// SetDigestWithInt64s put given int64 into digest.
func (d *MD5Digest) SetDigestWithInt64s(d0, d1 int64) {
	b := d.digest[:]
	binary.LittleEndian.PutUint64(b[0:], uint64(d0))
	binary.LittleEndian.PutUint64(b[8:], uint64(d1))
}

// Uint64s return digest in 2 unsigned int64.
func (d *MD5Digest) Uint64s() (d0, d1 uint64) {
	b := d.digest[:]
	d0 = binary.LittleEndian.Uint64(b[0:])
	d1 = binary.LittleEndian.Uint64(b[8:])
	return
}

// SetDigestWithUint64s put given unsigned int64 into digest.
func (d *MD5Digest) SetDigestWithUint64s(d0, d1 uint64) {
	b := d.digest[:]
	binary.LittleEndian.PutUint64(b[0:], d0)
	binary.LittleEndian.PutUint64(b[8:], d1)
}

func (d *MD5Digest) setDigestWithBytes(buf []byte) (err error) {
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

// SetDigestWithBase64RawURLString set digest with given base64url-nopadding encoded string.
func (d *MD5Digest) SetDigestWithBase64RawURLString(s string) (err error) {
	buf, err := base64.RawURLEncoding.DecodeString(s)
	if nil != err {
		return
	}
	d.setDigestWithBytes(buf)
	return
}

// Base64RawStdString return digest in base64std-nopadding encoded string.
func (d *MD5Digest) Base64RawStdString() string {
	return base64.RawStdEncoding.EncodeToString(d.digest[:])
}

// SetDigestWithBase64RawStdString set digest with given base64std-nopadding encoded string.
func (d *MD5Digest) SetDigestWithBase64RawStdString(s string) (err error) {
	buf, err := base64.RawStdEncoding.DecodeString(s)
	if nil != err {
		return
	}
	d.setDigestWithBytes(buf)
	return
}

// HexString return digest in hex encoded string.
func (d *MD5Digest) HexString() string {
	return hex.EncodeToString(d.digest[:])
}

// SetDigestWithHexString return digest in base64std-nopadding encoded string.
func (d *MD5Digest) SetDigestWithHexString(s string) (err error) {
	buf, err := hex.DecodeString(s)
	if nil != err {
		return
	}
	d.setDigestWithBytes(buf)
	return
}

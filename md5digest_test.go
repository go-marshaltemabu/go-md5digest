package md5digest_test

import (
	"crypto/md5"
	"testing"

	md5digest "github.com/go-marshaltemabu/go-md5digest"
)

func checkDigestCase1(t *testing.T, d *md5digest.MD5Digest) {
	i0, i1 := d.Uint64s()
	if i0 != 0x98b36899782e2f90 {
		t.Errorf("unexpect uint64[0]: 0x016%x", i0)
	}
	if i1 != 0xe0e7c86bb6d2fd4e {
		t.Errorf("unexpect uint64[1]: 0x016%x", i1)
	}
}

func TestDigestCase1a(t *testing.T) {
	chksum := md5.Sum([]byte("HelloWorld.\n"))
	var d1 md5digest.MD5Digest
	d1.SetDigest(&chksum)
	checkDigestCase1(t, &d1)
}

func TestDigestCase1b(t *testing.T) {
	var d1 md5digest.MD5Digest
	d1.SumString("HelloWorld.\n")
	checkDigestCase1(t, &d1)
	b64string := d1.Base64RawURLString()
	t.Logf("d1.Base64RawURLString: %s", b64string)
	var d2 md5digest.MD5Digest
	if err := d2.SetDigestWithBase64RawURLString(b64string); nil != err {
		t.Errorf("failed on d2.SetDigestWithBase64RawURLString: %v", err)
	}
	checkDigestCase1(t, &d2)
	if !d1.Equal(&d2) {
		t.Error("only inform when other size not equal")
	}
}

func TestDigestCase1c(t *testing.T) {
	var d1 md5digest.MD5Digest
	d1.SetDigestWithUint64s(0x98b36899782e2f90, 0xe0e7c86bb6d2fd4e)
	checkDigestCase1(t, &d1)
	var d2 md5digest.MD5Digest
	d2.SetDigestWithInt64s(-7443490750757720176, -2240601924639195826)
	checkDigestCase1(t, &d2)
	if !d1.Equal(&d2) {
		t.Error("only inform when other size not equal")
	}
	if b64str := d1.Base64RawURLString(); b64str != "kC8ueJlos5hO_dK2a8jn4A" {
		t.Errorf("unexpected base64url string (d1): %s", b64str)
	}
	if b64str := d2.Base64RawURLString(); b64str != "kC8ueJlos5hO_dK2a8jn4A" {
		t.Errorf("unexpected base64url string (d2): %s", b64str)
	}
}

func TestEqual1(t *testing.T) {
	var d1 md5digest.MD5Digest
	var d2 md5digest.MD5Digest
	var d3 md5digest.MD5Digest
	d1.SumString("HelloWorld.\n")
	d2.SumString("x")
	d3.SumBytes([]byte("HelloWorld.\n"))
	if d1.Equal(&d2) {
		t.Error("expect not equal for d1 and d2")
	}
	if d2.Equal(&d3) {
		t.Error("expect not equal for d2 and d3")
	}
	if !d1.Equal(&d3) {
		t.Error("expect equal for d1 and d3")
	}
	if !d3.Equal(&d1) {
		t.Error("expect equal for d3 and d1")
	}
	if !d1.Equal(&d1) {
		t.Error("expect equal for d1 and d1")
	}
}

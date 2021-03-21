package md5digest_test

import (
	"crypto/md5"
	"encoding/json"
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

func TestDigestCase1b64URL(t *testing.T) {
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
	if !d2.Equal(&d1) {
		t.Error("only inform when other size not equal")
	}
}

func TestDigestCase1b64Std(t *testing.T) {
	var d1 md5digest.MD5Digest
	d1.SumString("HelloWorld.\n")
	checkDigestCase1(t, &d1)
	b64string := d1.Base64RawStdString()
	t.Logf("d1.Base64RawStdString: %s", b64string)
	var d2 md5digest.MD5Digest
	if err := d2.SetDigestWithBase64RawStdString(b64string); nil != err {
		t.Errorf("failed on d2.SetDigestWithBase64RawStdString: %v", err)
	}
	checkDigestCase1(t, &d2)
	if !d1.Equal(&d2) {
		t.Error("only inform when other size not equal")
	}
	if !d2.Equal(&d1) {
		t.Error("only inform when other size not equal")
	}
}

func TestDigestCase1bHex(t *testing.T) {
	var d1 md5digest.MD5Digest
	d1.SumString("HelloWorld.\n")
	checkDigestCase1(t, &d1)
	hexString := d1.HexString()
	t.Logf("d1.HexString: %s", hexString)
	var d2 md5digest.MD5Digest
	if err := d2.SetDigestWithHexString(hexString); nil != err {
		t.Errorf("failed on d2.SetDigestWithHexString: %v", err)
	}
	checkDigestCase1(t, &d2)
	if !d1.Equal(&d2) {
		t.Error("only inform when other size not equal")
	}
	if !d2.Equal(&d1) {
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
	if b64str := d1.Base64RawStdString(); b64str != "kC8ueJlos5hO/dK2a8jn4A" {
		t.Errorf("unexpected base64std string (d1): %s", b64str)
	}
	if b64str := d2.Base64RawStdString(); b64str != "kC8ueJlos5hO/dK2a8jn4A" {
		t.Errorf("unexpected base64std string (d2): %s", b64str)
	}
	if hexStr := d1.HexString(); hexStr != "902f2e789968b3984efdd2b66bc8e7e0" {
		t.Errorf("unexpected hex string (d1): %s", hexStr)
	}
	if hexStr := d2.HexString(); hexStr != "902f2e789968b3984efdd2b66bc8e7e0" {
		t.Errorf("unexpected hex string (d2): %s", hexStr)
	}
}

func TestDigestCase1dJSONMarshal(t *testing.T) {
	var d1 md5digest.MD5Digest
	d1.SumString("HelloWorld.\n")
	buf1, err := json.Marshal(&d1)
	if nil != err {
		t.Errorf("json Marshal failed: %v", err)
	}
	if string(buf1) != "\"kC8ueJlos5hO_dK2a8jn4A\"" {
		t.Errorf("unexpect json encode result: %v", string(buf1))
	}
	checkDigestCase1(t, &d1)
}

func TestDigestCase1dJSONUnmarshal(t *testing.T) {
	jsonContent := []byte("\"kC8ueJlos5hO_dK2a8jn4A\"")
	var d1 md5digest.MD5Digest
	if err := json.Unmarshal(jsonContent, &d1); nil != err {
		t.Errorf("json Unmarshal failed: %v", err)
	}
	checkDigestCase1(t, &d1)
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

func TestEmpty1(t *testing.T) {
	d1 := md5digest.NewMD5DigestWithBase64RawURLString("kC8ueJlos5hO_dK2a8jn4A")
	checkDigestCase1(t, &d1)
	if d1.IsEmpty() {
		t.Errorf("d1 should not be empty")
	}
	var d2 md5digest.MD5Digest
	if !d2.IsEmpty() {
		t.Errorf("d2 should be empty")
	}
	if d1.Equal(&d2) {
		t.Error("expect not equal for d1 and d2")
	}
	d1.Clear()
	if !d1.IsEmpty() {
		t.Errorf("d1 should be empty")
	}
	if !d1.Equal(&d2) {
		t.Error("expect equal for d1 and d2")
	}
}

func BenchmarkJSONMarshal(b *testing.B) {
	var d1 md5digest.MD5Digest
	d1.SumString("HelloWorld.\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		json.Marshal(&d1)
	}
}

func BenchmarkJSONUnmarshal(b *testing.B) {
	var d1 md5digest.MD5Digest
	jsonContent := []byte("\"kC8ueJlos5hO_dK2a8jn4A\"")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		json.Unmarshal(jsonContent, &d1)
	}
}

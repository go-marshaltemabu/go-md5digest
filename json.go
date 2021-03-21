package md5digest

import (
	"crypto/md5"
	"encoding/base64"
)

const expectJSONDataSize = 22 + 2

// base64.RawURLEncoding.EncodedLen(md5.Size) == 22

/*
// MarshalJSON implements the json.Marshaler interface.
func (d *MD5Digest) MarshalJSON() (data []byte, err error) {
	enc := base64.RawURLEncoding
	data = make([]byte, expectJSONDataSize)
	enc.Encode(data[1:], d.digest[:])
	data[0] = '"'
	data[23] = '"'
	return
}
*/

// UnmarshalJSON implements the json.Unmarshaler interface.
func (d *MD5Digest) UnmarshalJSON(data []byte) (err error) {
	dlen := len(data)
	if dlen != expectJSONDataSize {
		err = &ErrIncorrectSize{
			ReceivedBufferSize: dlen,
		}
		return
	}
	enc := base64.RawURLEncoding
	n, err := enc.Decode(d.digest[:], data[1:23])
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

/*

// The implementation above benchmarked into the following result:
//
// BenchmarkJSONMarshal
// BenchmarkJSONMarshal-4     	 1832948	       645 ns/op
// BenchmarkJSONUnmarshal
// BenchmarkJSONUnmarshal-4   	 2464780	       497 ns/op

// Use TextMarshaler and TextUnmarshaler (w/o MarshalJSON and UnmarshalJSON)
// benchmarked into the following result:
//
// BenchmarkJSONMarshal
// BenchmarkJSONMarshal-4     	 3126555	       357 ns/op
// BenchmarkJSONUnmarshal
// BenchmarkJSONUnmarshal-4   	 1830906	       670 ns/op

// The implementation below benchmarked into the following result:
//
// BenchmarkJSONMarshal
// BenchmarkJSONMarshal-4     	  976476	      1132 ns/op
// BenchmarkJSONUnmarshal
// BenchmarkJSONUnmarshal-4   	 1000000	      1232 ns/op

import (
	"encoding/json"
)

// MarshalJSON implements the json.Marshaler interface.
func (d *MD5Digest) MarshalJSON() ([]byte, error) {
	strValue := d.Base64RawURLString()
	return json.Marshal(strValue)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (d *MD5Digest) UnmarshalJSON(data []byte) (err error) {
	var strValue string
	if err = json.Unmarshal(data, &strValue); nil != err {
		return
	}
	if err = d.SetDigestWithBase64RawURLString(strValue); nil != err {
		return
	}
	return
}

*/

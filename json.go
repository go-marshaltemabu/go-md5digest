package md5digest

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

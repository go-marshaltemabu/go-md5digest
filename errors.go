package md5digest

import (
	"crypto/md5"
	"strconv"
)

// ErrIncorrectSize indicate given buffer size is not correct.
type ErrIncorrectSize struct {
	ReceivedBufferSize int
}

func (e ErrIncorrectSize) Error() string {
	return "[ErrIncorrectSize: expect=" + strconv.FormatInt(md5.Size, 10) + ", got=" + strconv.FormatInt(int64(e.ReceivedBufferSize), 10) + "]"
}

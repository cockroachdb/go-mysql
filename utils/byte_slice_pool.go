package utils

import "sync"

type ByteSlice struct {
	B []byte
}

func (b *ByteSlice) Write(p []byte) (n int, err error) {
	b.B = append(b.B, p...)
	return len(p), nil
}

var (
	byteSlicePool = sync.Pool{
		New: func() interface{} {
			return new(ByteSlice)
		},
	}

	byteSlicePoolResult = sync.Pool{
		New: func() interface{} {
			return new(ByteSlice)
		},
	}
)

func ByteSliceGet(length int) *ByteSlice {
	data := byteSlicePool.Get().(*ByteSlice)
	if cap(data.B) < length {
		data.B = make([]byte, length)
	} else {
		data.B = data.B[:length]
	}
	return data
}

func ByteSlicePut(data *ByteSlice) {
	data.B = data.B[:0]
	byteSlicePool.Put(data)
}

func ByteSliceResultGet(length int) *ByteSlice {
	data := byteSlicePoolResult.Get().(*ByteSlice)
	if cap(data.B) < length {
		data.B = make([]byte, length)
	} else {
		data.B = data.B[:length]
	}
	return data
}

func ByteSliceResultPut(data *ByteSlice) {
	data.B = data.B[:0]
	byteSlicePoolResult.Put(data)
}

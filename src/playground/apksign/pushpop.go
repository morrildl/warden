package apksign

import (
	"encoding/binary"
)

/* This idiom is very common in the v2 Android signing scheme:
   val := binary.LittleEndian.Uint32(buf) // parse 4 bytes into a uint32
	 buf = buf[4:]													// advance the buffer past the "consumed" bytes

	 ...and same for uint64 values.

	 It's not a lot of code but when it appears many times in succession it detracts from readability
	 and is prone to typos and copy/paste bugs. So we wrap this in a few convenience functions to
	 improve this. The compiler generally seems to inline calls to these.
*/

func pop32(in []byte) (uint32, []byte) {
	return binary.LittleEndian.Uint32(in[:4]), in[4:]
}

func pop64(in []byte) (uint64, []byte) {
	return binary.LittleEndian.Uint64(in[:8]), in[8:]
}

func popN(in []byte, count int) ([]byte, []byte) {
	return in[:count], in[count:]
}

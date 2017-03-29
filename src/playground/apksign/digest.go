package apksign

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"

	"playground/log"
)

type Digester struct {
	file       *os.File
	size       int64
	asv2Offset uint64
	cdOffset   uint64
	eocdOffset uint64
	newHash    crypto.Hash
}

func DigesterFromZip(z *Zip, newHash crypto.Hash) *Digester {
	return &Digester{
		z.file, z.size, z.asv2Offset, z.cdOffset, z.eocdOffset, newHash,
	}
}

// ChunkedFileDigest implements the Android APK Signing Scheme v2 Merkel-tree-flavored block
// digesting algorithm. As the algorithm was specifically designed to be parallelizable, we
// parallelize it via goroutines.
func (d *Digester) ChunkedFileDigest() ([]byte, error) {
	// Per spec, we have to... "revise"... the EOCD block so that its pointer to the CD actually
	// points to the offset of the ASv2 block. This is because as the ASv2 block changes in length,
	// it changes the CD offset. Since the ASv2 block is added after the fact and a changing EOCD
	// would alter the hash, the CD is pointed to the ASv2 before being sent to be hashed.
	// Essentially, this hashes the "pristine" Zip, as it would be if the ASv2 block didn't exist.
	//
	// Note that this is a RAM-only operation for signing purposes; on disk, this would be an invalid
	// Zip file.
	log.Debug("ChunkedFileDigest", "entry")
	var endOfFileSection uint64
	revisedEOCD := make([]byte, uint64(d.size)-d.eocdOffset)
	d.file.Seek(int64(d.eocdOffset), 0)
	n, err := io.ReadFull(d.file, revisedEOCD)
	if err != nil {
		return nil, err
	}
	if d.asv2Offset > 0 {
		if uint64(n) != uint64(d.size)-d.eocdOffset {
			return nil, errors.New("short read on EOCD")
		}
		binary.LittleEndian.PutUint32(revisedEOCD[16:20], uint32(d.asv2Offset))

		endOfFileSection = d.asv2Offset
	} else {
		endOfFileSection = d.cdOffset
	}

	// hash the main block before the ASv2 block where file data lives
	pendingHashers, err := parallelFileHash(d.file, 0, endOfFileSection, d.newHash.New)
	if err != nil {
		return nil, err
	}

	// hash the Central Directory (which is highly likely to be << 1MB unless the APK is fscking enormous
	tmp, err := parallelFileHash(d.file, d.cdOffset, d.eocdOffset-d.cdOffset, d.newHash.New)
	if err != nil {
		return nil, err
	}
	pendingHashers = append(pendingHashers, tmp...)

	// hash the modified End Of Central Directory block
	pendingHashers = append(pendingHashers, parallelBufferHash(d.file, revisedEOCD, d.newHash.New)...) // modified EOCD

	// pendingHashers now contains a bunch of channels, in order, corresponding to digests of
	// individual blocks; so now roll up their results into the final hash
	numChunks := make([]byte, 4)
	binary.LittleEndian.PutUint32(numChunks, uint32(len(pendingHashers)))
	accumHash := d.newHash.New()
	accumHash.Write([]byte{0x5a})
	accumHash.Write(numChunks)
	for _, c := range pendingHashers {
		b := <-c
		log.Debug("ChunkedFileDigest", "chunk hash", hex.EncodeToString(b))
		_, err := io.Copy(accumHash, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
	}
	sum := accumHash.Sum(nil)
	log.Debug("ChunkedFileDigest", "final hash", hex.EncodeToString(sum))
	return sum, nil
}

func parallelFileHash(f *os.File, start, count uint64, newHash func() hash.Hash) ([]chan []byte, error) {
	hasher := func(d []byte, h hash.Hash, c chan []byte) {
		h.Write(d)
		c <- h.Sum(nil)
	}
	var ret []chan []byte
	f.Seek(int64(start), 0)
	for count > 0 {
		c := make(chan []byte)
		var buf []byte
		var l uint32
		if count < 1048576 {
			buf = make([]byte, count+5)
			l = uint32(count)
		} else {
			buf = make([]byte, 1048576+5)
			l = 1048576
		}
		buf[0] = 0xa5
		binary.LittleEndian.PutUint32(buf[1:5], l)
		n, err := io.ReadFull(f, buf[5:])
		if err != nil {
			return nil, err
		}
		count -= uint64(n)
		go hasher(buf, newHash(), c)
		ret = append(ret, c)
	}

	return ret, nil
}

func parallelBufferHash(f *os.File, inbuf []byte, newHash func() hash.Hash) []chan []byte {
	hasher := func(d []byte, h hash.Hash, c chan []byte) {
		h.Write(d)
		c <- h.Sum(nil)
	}
	var ret []chan []byte
	count := len(inbuf)
	for count > 0 {
		c := make(chan []byte)
		var buf []byte
		var l uint32
		if count < 1048576 {
			buf = make([]byte, count+5)
			copy(buf[5:], inbuf[:count])
			l = uint32(count)
			count = 0
		} else {
			buf = make([]byte, 1048576+5)
			copy(buf[5:], inbuf[:1048576])
			l = 1048576
			count -= 1048576
			inbuf = inbuf[1048576:]
		}
		buf[0] = 0xa5
		binary.LittleEndian.PutUint32(buf[1:5], l)
		go hasher(buf, newHash(), c)
		ret = append(ret, c)
	}

	return ret
}

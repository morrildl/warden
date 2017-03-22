package apksign

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"os"
)

/* See https://source.android.com/security/apksigning/v2.html */

type Digest struct {
	AlgorithmID uint32
	Digest      []byte
}

type Attribute struct {
	ID    uint32
	Value []byte
}

type SignedData struct {
	Digests    []*Digest
	Certs      []*x509.Certificate
	Attributes []*Attribute
	Raw        []byte // used to store raw bytes for signing & verifying
}

type Signature struct {
	AlgorithmID uint32
	Signature   []byte
}

type Signer struct {
	SignedData *SignedData
	Signatures []*Signature
	PublicKey  []byte
}

type V2Block struct {
	Signers []*Signer
}

func ParseV2Block(block []byte) (*V2Block, error) {
	var size32 uint32

	v2 := &V2Block{}

	// check the key/value pair block; we expect only one entry, w/ key 0x7109871a (meaning signature v2 specifically)
	asv2Len, block := pop64(block)
	if uint64(len(block)) != asv2Len {
		return nil, errors.New("unsupported: multiple ID/Value pair blocks at top level")
		// So there are 3 reasons there might be multiple blocks here:
		//
		// 1. there is a duplicate v2 signing block, which is probably an attack (i.e. attempt to break verification)
		// 2. there is a v3 or later signing block, which doesn't exist at time of this writing and we can't cope with
		//    (Android itself has to be able to deal with this, but we don't)
		// 3. someone added a block with their own ID in here as a way to store some random data
		//
		// The spec says "ID-value pairs with unknown IDs should be ignored when interpreting the
		// block", so only #1 should be fatal here, technically. But out of an abundance of caution we
		// abort anyway. This can be fixed later if there's an actual need to; this should be fine for
		// the forseeable future.
	}

	// verify the block ID
	size32, block = pop32(block)
	if size32 != 0x7109871a {
		return nil, errors.New("unsupported: not an Android v2 signature block")
		// note that even when/if they add a v3 signing scheme, we still should error out here b/c we
		// won't know how to handle it anyway
	}

	// we now know we have exactly 1 signature block, w/ ID 0x7109871a, of length size64 - 4

	// now extract out all the signer blocks
	size32, block = pop32(block) // length of all signer blocks combined
	for len(block) > 0 {
		var signer []byte
		if len(block) < 5 { // 4 bytes for size prefix plus at least 1 byte for data
			return nil, errors.New("malformed signing block - short signer")
		}
		size32, block = pop32(block)
		if size32 > uint32(len(block)) {
			return nil, errors.New("malformed signing block - long signer")
		}

		// handle current signer block
		signer, block = popN(block, int(size32))
		s, err := ParseSigner(signer)
		if err != nil {
			return nil, err
		}
		if s != nil {
			v2.Signers = append(v2.Signers, s)
		}
	}

	return v2, nil
}

func ParseSignedData(sd []byte) (*SignedData, error) {
	raw := make([]byte, len(sd))
	copy(raw, sd)

	if len(sd) < 12 {
		return nil, errors.New("malformed signed data block - not even enough bytes for length prefixes")
	}

	// digests section
	var digestsLen uint32
	var digestsBytes []byte
	var digests []*Digest
	digestsLen, sd = pop32(sd)
	if digestsLen > uint32(len(sd))-8 || digestsLen < 4 {
		return nil, errors.New("malformed signed data block - bogus digests sub block")
	}
	digestsBytes, sd = popN(sd, int(digestsLen))
	for len(digestsBytes) > 0 {
		if len(digestsBytes) < 9 {
			return nil, errors.New("malformed digests block - not enough bytes")
		}
		var algID, digestLen, curBlockLen uint32
		var curDigestBytes []byte
		curBlockLen, digestsBytes = pop32(digestsBytes)
		if int(curBlockLen) > len(digestsBytes) {
			return nil, errors.New("malformed digests block - long count")
		}
		algID, digestsBytes = pop32(digestsBytes)
		digestLen, digestsBytes = pop32(digestsBytes)
		curDigestBytes, digestsBytes = popN(digestsBytes, int(digestLen))

		digests = append(digests, &Digest{algID, curDigestBytes})
	}

	// certificates section
	var certsLen, curCert uint32
	var certsBytes, curCertBytes []byte
	var certs []*x509.Certificate
	certsLen, sd = pop32(sd)
	if certsLen > uint32(len(sd)) {
		return nil, errors.New("malformed certificates block - long length")
	}
	certsBytes, sd = popN(sd, int(certsLen))
	for len(certsBytes) > 0 {
		if len(certsBytes) < 5 {
			return nil, errors.New("malformed certificates block - not enough bytes for a cert")
		}
		curCert, certsBytes = pop32(certsBytes)
		curCertBytes, certsBytes = popN(certsBytes, int(curCert))
		parsedCerts, err := x509.ParseCertificates(curCertBytes)
		if err != nil {
			return nil, err
		}
		if parsedCerts == nil || len(parsedCerts) < 1 {
			return nil, errors.New("malformed signed data block - missing cert")
		}
		certs = append(certs, parsedCerts[0])
	}

	// additional attributes section
	var attrsLen, attrID uint32
	var attrsBytes []byte
	var attrs []*Attribute
	attrsLen, sd = pop32(sd)
	if attrsLen > uint32(len(sd)) {
		return nil, errors.New("malformed attributes block - long length")
	}
	attrsBytes, sd = popN(sd, int(attrsLen))
	for len(attrsBytes) > 0 {
		if len(attrsBytes) < 5 {
			return nil, errors.New("malformed attributes block - not enough bytes for key and value")
		}
		attrID, attrsBytes = pop32(attrsBytes)
		attrs = append(attrs, &Attribute{attrID, attrsBytes}) // TODO: probably need to copy these bytes
	}

	if len(sd) != 0 {
		return nil, errors.New("malformed signed data block - extra bytes")
	}

	return &SignedData{digests, certs, attrs, raw}, nil
}

func ParseSignature(sigs []byte) ([]*Signature, error) {
	var ret []*Signature
	var size, algID, sigSize uint32
	var sig []byte

	for len(sigs) > 0 {
		if len(sigs) < 5 {
			return nil, errors.New("malformed signatures block - short sig block")
		}

		size, sigs = pop32(sigs) // size of current signature
		algID, sigs = pop32(sigs)
		sigSize, sigs = pop32(sigs)
		sig, sigs = popN(sigs, int(sigSize))

		if sigSize+4+4 != size {
			return nil, errors.New("malformed signatures block - mismatched sizes")
		}

		ret = append(ret, &Signature{algID, sig})
	}

	return ret, nil
}

func ParseSigner(signer []byte) (*Signer, error) {
	if len(signer) < 12 {
		return nil, errors.New("malformed signer block - not even enough for size prefixes")
	}

	var size32 uint32

	// handle signed data sub block
	size32, signer = pop32(signer) // length of signed data section
	if size32 < 12 {
		return nil, errors.New("malformed signed data block - not even enough for size prefixes")
	}
	if size32 > uint32(len(signer)) {
		return nil, errors.New("malformed signed data block - longer than available bytes")
	}
	var signedData []byte
	signedData, signer = popN(signer, int(size32))

	sds, err := ParseSignedData(signedData)
	if err != nil {
		return nil, err
	}
	if sds == nil {
		return nil, errors.New("malformed signed data block - block is empty")
	}

	// handle signatures sub block
	if len(signer) < 8 {
		return nil, errors.New("malformed or missing signature block")
	}
	size32, signer = pop32(signer) // size of signature block
	if size32 < 4 {
		return nil, errors.New("malformed signature block - not even enough for size prefixes")
	}
	if size32 > uint32(len(signer))-4 {
		return nil, errors.New("malformed signature block - longer than available bytes")
	}
	var signatures []byte
	signatures, signer = popN(signer, int(size32))
	ss, err := ParseSignature(signatures)
	if err != nil {
		return nil, err
	}
	if ss == nil {
		return nil, errors.New("malformed signatures block - block is empty")
	}

	// handle public key sub block
	if len(signer) < 4 {
		return nil, errors.New("malformed or missing public key block")
	}
	size32, signer = pop32(signer)
	if size32 != uint32(len(signer)) {
		return nil, errors.New("malformed signed data block - erroneous public key length")
	}
	publicKey := signer[:]

	return &Signer{sds, ss, publicKey}, nil
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

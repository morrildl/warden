package apksign

import (
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"errors"

	"playground/log"
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
		log.Debug("ParseV2Block", "unsupported: multiple ID/Value pair blocks at top level", asv2Len, len(block))
		return nil, errors.New("unsupported: multiple ID/Value pair blocks at top level")
		// So there are 3 reasons there might be multiple blocks here:
		//
		// 1. there is a second v2 signing block, which is probably an attack (i.e. attempt to break verification)
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
	if size32 != uint32(len(block)) {
		return nil, errors.New("spurious data after signers sequence")
	}
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

func (v2 *V2Block) Sign(z *Zip, keys []*SigningKey) error {
	v2.Signers = make([]*Signer, 0)

	// the ASv2 scheme spec does not actually forbid having multiple 'signer' blocks with the same
	// public keymatter, but the clear intention is that these be grouped; so first, batch up
	// SigningKeys that share the same hash
	keyMap := make(map[string][]*SigningKey)
	for _, sk := range keys {
		cfgs, ok := keyMap[sk.certHash]
		if !ok {
			cfgs = make([]*SigningKey, 0)
		}
		keyMap[sk.certHash] = append(cfgs, sk)
	}

	for _, sks := range keyMap {
		s := &Signer{}
		s.SignedData = &SignedData{}
		s.Signatures = make([]*Signature, 0)
		s.PublicKey = make([]byte, len(sks[0].Certificate.RawSubjectPublicKeyInfo))
		copy(s.PublicKey, sks[0].Certificate.RawSubjectPublicKeyInfo)
		s.SignedData.Certs = []*x509.Certificate{sks[0].Certificate} // certHash guarantees these are all the same
		s.SignedData.Digests = make([]*Digest, 0)

		// each entry under the same cert will differ as a tuple of (KeyType, HashType), which is "algorithm ID" per ASv2
		for _, sk := range sks {
			log.Debug("loop", "loop")
			d := &Digest{}
			sig := &Signature{}

			var algoID uint32
			var hasher crypto.Hash
			switch sk.Type {
			case RSA:
				switch sk.Hash {
				case SHA256:
					algoID = 0x0103
					hasher = crypto.SHA256
				case SHA512:
					algoID = 0x0104
					hasher = crypto.SHA512
				default:
					return errors.New("unsupported hash algorithm specified")
				}
			default:
				return errors.New("unsupported key type specified")
			}

			var err error
			dg := DigesterFromZip(z, hasher)
			d.AlgorithmID = algoID
			sig.AlgorithmID = algoID
			d.Digest, err = dg.ChunkedFileDigest()
			if err != nil {
				return err
			}

			s.SignedData.Digests = append(s.SignedData.Digests, d)
			s.Signatures = append(s.Signatures, sig)
		}

		sd := s.SignedData.Marshal()
		for i, sk := range sks {
			var hasher crypto.Hash
			var err error
			switch sk.Type {
			case RSA:
				switch sk.Hash {
				case SHA256:
					hasher = crypto.SHA256
				case SHA512:
					hasher = crypto.SHA512
				}
			}

			sig := s.Signatures[i]

			sig.Signature, err = sk.Sign(sd, hasher)
			if err != nil {
				return err
			}
		}

		v2.Signers = append(v2.Signers, s)
	}

	// at this point we have a fully populated ASv2 tree representation, so now we just marshal it to []byte
	blocks := make([][]byte, 0)
	for _, signer := range v2.Signers {
		blocks = append(blocks, push32(signer.Marshal()))
	}
	signers := concat(blocks...)
	asv2 := push32(signers)

	// asv2Value now contains the concatenation of all 'signers' blocks; this will be the value of the
	// signing-block attr in the outermost ASv2 block wrapper

	// add the key for the signing block
	asv2 = push32(asv2) // add 4 bytes for the magic ID
	binary.LittleEndian.PutUint32(asv2[:4], 0x7109871a)

	// add the length prefix for the ID/value pair
	asv2 = push64(asv2)

	// create & write the final block
	finalSize := len(asv2) + 8 + 16    // size is key/value portion + uint64 footer size + 16-byte footer magic string
	final := make([]byte, finalSize+8) // need another uint64 to prepend another copy of size
	binary.LittleEndian.PutUint64(final[:8], uint64(finalSize))
	copy(final[8:], asv2)
	binary.LittleEndian.PutUint64(final[8+len(asv2):], uint64(finalSize))
	copy(final[len(final)-16:], []byte("APK Sig Block 42"))

	_, er := ParseV2Block(asv2)
	if er != nil {
		return er
	}

	// now we have the final bytes, tell the Zip to inject them into its .zip file at the appropriate location
	err := z.InjectBeforeCD(final)
	if err != nil {
		return err
	}

	// huzzah, it's done
	return nil
}

func (s *Signer) Marshal() []byte {
	if s == nil {
		return nil
	}

	sd := push32(s.SignedData.Marshal())

	ses := make([][]byte, 0)
	for _, s := range s.Signatures {
		ses = append(ses, push32(s.Marshal()))
	}
	sigs := push32(concat(ses...))
	pk := push32(s.PublicKey)
	return concat(sd, sigs, pk)
}

func (sd *SignedData) Marshal() []byte {
	if sd == nil {
		return nil
	}

	// Digests
	blocks := make([][]byte, 0)
	for _, d := range sd.Digests {
		blocks = append(blocks, push32(d.Marshal()))
	}
	digests := push32(concat(blocks...))

	// Certs
	blocks = make([][]byte, 0)
	for _, c := range sd.Certs {
		blocks = append(blocks, push32(c.Raw))
	}
	certs := push32(concat(blocks...))

	// Attributes
	blocks = make([][]byte, 0)
	for _, a := range sd.Attributes {
		blocks = append(blocks, push32(a.Marshal()))
	}
	attrs := push32(concat(blocks...))

	return concat(digests, certs, attrs)
}

func (s *Signature) Marshal() []byte {
	if s == nil {
		return nil
	}

	sig := push32(push32(s.Signature)) // abuse push32 w/ a 2nd call as a cheesy way to allocate a suitable slice
	binary.LittleEndian.PutUint32(sig[:4], s.AlgorithmID)
	return sig
}

func (a *Attribute) Marshal() []byte {
	if a == nil {
		return nil
	}

	attr := push32(a.Value) // abuse push32 as a cheesy way to allocate a buffer of suitable size
	binary.LittleEndian.PutUint32(attr[:4], a.ID)
	return attr
}

func (d *Digest) Marshal() []byte {
	if d == nil {
		return nil
	}

	digest := push32(push32(d.Digest)) // abuse push32 w/ a 2nd call as a cheesy way to allocate a suitable slice
	binary.LittleEndian.PutUint32(digest[:4], d.AlgorithmID)
	return digest
}

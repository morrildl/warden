package apksign

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"os"
	"time"

	"playground/log"
)

// This package contains a class for performing certain operations on ZIP files required for signing
// Android APKs. In particular, it supports the "Android Signing Scheme v2" introduced in Nougat.
// See https://source.android.com/security/apksigning/v2.html

type Zip struct {
	fileName   string
	file       *os.File
	size       int64
	modified   time.Time
	eocdOffset uint64
	cdOffset   uint64
	asv2Offset uint64
	rawASv2    []byte
}

func NewZip(file string) (*Zip, error) {
	var err error
	z := &Zip{}
	z.fileName = file
	if z.file, err = os.Open(file); err != nil {
		return nil, err
	}
	fi, err := z.file.Stat()
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, errors.New("input is a directory")
	}
	z.size = fi.Size()
	z.modified = fi.ModTime()

	// now scan for key offsets: Central Directory (CD) table; End Of Central Directory (EOCD) table;
	// and the Android Signing Scheme v2 block (ASv2). If the file lacks either a CD or EOCD, it
	// cannot be a Zip at all; if it lacks an ASv2 block it just means it isn't signed under that
	// scheme. It could still be v1 signed. Note that we don't do much parsing of either the CD or
	// EOCD tables -- this isn't a general-purpose zip utility.

	if z.size < 22 { // cannot possibly be a ZIP
		return nil, errors.New("input is too small to be a zip")
	}

	b := make([]byte, 22)
	for i := uint32(0); i < 65535; i++ {
		// The "end of central directory" block has 22 bytes of fixed headers, followed by a variable
		// length comment, whose length is stored in the final 16 bits of the EOCD block. This means
		// that we can't just look at EOF - 22 for the EOCD magic identifier, we have to read backward
		// to accommodate a possible zip file comment.

		z.file.Seek(z.size-22-int64(i), 0)
		n, err := z.file.Read(b)
		if err != nil {
			return nil, err
		}
		if n < 22 {
			return nil, errors.New("short read on EOCD fetch")
		}

		// check for the EOCD magic string, 0x06054b50. note that zip files are little endian
		if binary.LittleEndian.Uint32(b[:4]) == 0x06054b50 {
			// we now have a candidate, but we don't know for sure that this is the EOCD: the comment
			// could technically contain the EOCD magic. so verify that the number of bytes we've read
			// backward matches what the EOCD should say is the comment length. This also covers this
			// verification requirement:
			// Spec: "verify that ... ZIP End of Central Directory is not followed by more data"
			commentLen := binary.LittleEndian.Uint16(b[20:22])
			if uint16(i) != commentLen {
				continue // can't be the EOCD; keep going
			}

			// comment length checks out, but that could be a coincidence, so also check CD offset, which we need anyway
			candidateEOCD := uint64(z.size) - 22 - uint64(i)
			eocdCD := binary.LittleEndian.Uint32(b[16:20])
			eocdCDLen := binary.LittleEndian.Uint32(b[12:16])
			b2 := make([]byte, 4)
			z.file.Seek(int64(eocdCD), 0)
			n, err = z.file.Read(b2)
			if err != nil {
				return nil, err
			}
			if n < 4 {
				return nil, errors.New("short read on CD fetch")
			}
			if binary.LittleEndian.Uint32(b2) != 0x02014b50 {
				continue // CD pointed to by "EOCD" is not a valid CD, but there may still be comment bytes to unwind
			}

			// Spec: "verify that ... ZIP Central Directory is immediately followed by ZIP End of Central Directory record"
			if uint64(eocdCD)+uint64(eocdCDLen) != candidateEOCD {
				return nil, errors.New("CD not adjacent to EOCD")
			}

			// now we have an EOCD that checks out and appears to point to a CD, so we are pretty sure this is a zip file
			z.cdOffset = uint64(eocdCD)
			z.eocdOffset = candidateEOCD

			// now see if there is an Android signing v2 block
			z.file.Seek(int64(z.cdOffset)-16, 0)
			magic := make([]byte, 16)
			z.file.Read(magic)
			if string(magic) != "APK Sig Block 42" {
				return z, nil
			}

			// it has the ASv2 magic in the expected spot, so check size field & compute offset
			b64 := make([]byte, 8)
			z.file.Seek(int64(z.cdOffset-16-8), 0) // size field is uint64 & is repeated at start & end of block
			z.file.Read(b64)
			postSize := binary.LittleEndian.Uint64(b64)
			z.file.Seek(int64(int64(z.cdOffset)-int64(postSize)-8), 0) // size includes magic & 2nd size field but not 1st
			z.file.Read(b64)
			preSize := binary.LittleEndian.Uint64(b64)
			if preSize == postSize { // Spec: "Two size fields of APK Signing Block contain the same value"
				z.asv2Offset = z.cdOffset - postSize - 8
			}

			log.Debug("Zip.New", "ASv2, CD, EOCD", z.asv2Offset, z.cdOffset, z.eocdOffset)

			return z, nil
		}
	}

	// if we fall past the end of the loop, means we exhausted all possibility of it being a zip
	return nil, errors.New("input is not a zip")
}

func (z *Zip) IsAPK() bool {
	r, err := zip.NewReader(z.file, z.size)
	if err != nil {
		log.Warn("Zip.IsAPK", "error opening with zip library", err)
		return false
	}

	// in determining whether it looks like an APK, we just look for 4 key files
	hasClassesDex := false
	hasAndroidManifestXML := false
	hasResourcesARSC := false
	hasManifest := false
	for _, f := range r.File {
		if f.FileHeader.Name == "classes.dex" {
			hasClassesDex = true
		} else if f.FileHeader.Name == "AndroidManifest.xml" {
			hasAndroidManifestXML = true
		} else if f.FileHeader.Name == "resources.arsc" {
			hasResourcesARSC = true
		} else if f.FileHeader.Name == "META-INF/MANIFEST.MF" {
			hasManifest = true
		}
		if hasClassesDex && hasAndroidManifestXML && hasResourcesARSC && hasManifest {
			// given that Android SDK almost always inserts resources.arsc at the very end of the ZIP,
			// this will probably never early-break, but eh can't hurt
			break
		}
	}

	return hasClassesDex && hasAndroidManifestXML && hasResourcesARSC && hasManifest
}

func (z *Zip) IsAPKv1Signed() bool {
	panic("v1 signing support not implemented yet")
	return false
}

func (z *Zip) loadRawASv2() error {
	if z.asv2Offset == 0 {
		return errors.New("not asv2 signed")
	}
	if z.rawASv2 == nil {
		block, err := z.extractASv2Block()
		if err != nil {
			return err
		}
		z.rawASv2 = make([]byte, len(block))
		copy(z.rawASv2, block)
	}
	return nil
}

func (z *Zip) IsAPKv2Signed() bool {
	err := z.loadRawASv2()
	if err != nil {
		return false
	}
	v2block, err := ParseV2Block(z.rawASv2)
	return err == nil && v2block != nil
}

func (z *Zip) VerifyV1() bool {
	panic("v1 signing support not implemented yet")
	return false
}

func (z *Zip) VerifyV2() bool {
	err := z.loadRawASv2()
	if err != nil {
		return false
	}
	v2block, err := ParseV2Block(z.rawASv2)
	if err != nil || v2block == nil {
		log.Debug("VerifyV2", "failed during parse", err)
		return false
	}

	// extractASv2Block() handles these 3 requirements from the Spec:
	// "Two size fields of APK Signing Block contain the same value."
	// "ZIP Central Directory is immediately followed by ZIP End of Central Directory record."
	// "ZIP End of Central Directory is not followed by more data."

	// Spec: "Verification succeeds if at least one signer was found and step 3 succeeded for each found signer."
	if len(v2block.Signers) < 1 {
		return false
	}
	for _, signer := range v2block.Signers {
		var sig *Signature
		var dig *Digest
		var algoID uint32

		// Spec: "Choose the strongest supported signature algorithm ID from signatures. The strength
		// ordering is up to each implementation/platform version."
		// TODO: Currently we only support RSA, as our primary purpose is signing. Expanding this is fairly
		// straightforward, though low priority
		for i, s := range signer.Signatures {
			if s.AlgorithmID == 0x0103 || s.AlgorithmID == 0x0104 && s.AlgorithmID > algoID {
				// ignore non-RSA algorithms for now, and favor SHA512 if it's present
				algoID = s.AlgorithmID
				sig = s
				dig = signer.SignedData.Digests[i]
			}
		}
		if algoID == 0 {
			log.Debug("VerifyV2", "unknown algorithm ID in Signature")
			return false // we don't know how to verify
		}

		// Spec: "Verify the corresponding signature from signatures against signed data using public key."
		pubkey, err := x509.ParsePKIXPublicKey(signer.PublicKey)
		if err != nil {
			log.Debug("VerifyV2", "error parsing RSA key", err)
			return false
		}
		switch pubkey.(type) {
		case *rsa.PublicKey:
		default:
			return false
		}
		switch algoID {
		case 0x0103:
			hashed := sha256.Sum256(signer.SignedData.Raw)
			err = rsa.VerifyPKCS1v15(pubkey.(*rsa.PublicKey), crypto.SHA256, hashed[:], sig.Signature)
			if err != nil {
				log.Debug("VerifyV2", "RSA verification failure (0x0103)", err)
				return false
			}
		case 0x0104:
			hashed := sha512.Sum512(signer.SignedData.Raw)
			err = rsa.VerifyPKCS1v15(pubkey.(*rsa.PublicKey), crypto.SHA512, hashed[:], sig.Signature)
			if err != nil {
				log.Debug("VerifyV2", "RSA verification failure (0x0104)", err)
				return false
			}
		default:
			return false
		}

		// Spec: "Verify that the ordered list of signature algorithm IDs in digests and signatures is identical."
		if len(signer.Signatures) != len(signer.SignedData.Digests) {
			log.Debug("VerifyV2", "signature/digest length mismatch", len(signer.Signatures), len(signer.SignedData.Digests))
			return false
		}
		for i := range signer.Signatures {
			if signer.Signatures[i].AlgorithmID != signer.SignedData.Digests[i].AlgorithmID {
				log.Debug("VerifyV2", "signature/digest algorithm mismatch", signer.Signatures[i].AlgorithmID, signer.SignedData.Digests[i].AlgorithmID)
				return false
			}
		}

		// Spec: "Compute the digest of APK contents using the same digest algorithm as the digest
		// algorithm used by the signature algorithm. Verify that the computed digest is identical to the
		// corresponding digest from digests."
		var newHash crypto.Hash
		switch algoID {
		case 0x0103:
			newHash = crypto.SHA256
		case 0x0104:
			newHash = crypto.SHA512
		default:
			return false // this should not be possible due to similar switch above, though
		}

		d := DigesterFromZip(z, newHash)
		ourDigest, err := d.ChunkedFileDigest()
		if err != nil {
			log.Debug("VerifyV2", "digester failure", err)
			return false
		}

		ok := bytes.Equal(ourDigest, dig.Digest)
		if !ok {
			log.Debug("VerifyV2", "hash mismatch")
			return false
		}

		// Spec: "Verify that SubjectPublicKeyInfo of the first certificate of certificates is identical
		// to public key."
		signer := v2block.Signers[0]
		cpk := signer.SignedData.Certs[0].RawSubjectPublicKeyInfo
		ok = bytes.Equal(cpk, signer.PublicKey)
		if !ok {
			log.Debug("VerifyV2", "SubjectPublicKeyInfo mismatch")
			return false
		}
	}

	return true
}

func (z *Zip) SignV1(out string) error {
	return errors.New("v1 signing support not implemented yet")
}

func (z *Zip) SignV2(keys []*SigningKey) error {
	for _, sk := range keys {
		if err := sk.Resolve(); err != nil {
			return err
		}
	}

	v2 := V2Block{}
	if err := v2.Sign(z, keys); err != nil {
		return err
	}
	return nil
}

func (z *Zip) extractASv2Block() ([]byte, error) {
	b64 := make([]byte, 8)
	z.file.Seek(int64(z.asv2Offset), 0)
	if n, err := z.file.Read(b64); err != nil || n < 8 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("not enough bytes available to read size")
	}
	size := binary.LittleEndian.Uint64(b64)

	var fi os.FileInfo
	fi, err := z.file.Stat()
	if err != nil {
		return nil, err
	}
	if (z.asv2Offset + uint64(size)) > (uint64(fi.Size()) - 22) {
		// if indicated size extends past the max possible w/o running into the EOCD, we know it's not
		// an ASv2 block
		log.Debug("extractASv2Block", "short block", z.asv2Offset, z.size, fi.Size())
		return nil, errors.New("requested ASv2 block is too short")
	}

	b := make([]byte, size)
	z.file.Read(b)

	// check for the magic string at end of block; compare header/footer sizes to make sure they match
	if string(b[len(b)-16:]) != "APK Sig Block 42" {
		return nil, errors.New("missing ASv2 sig block magic")
	}
	if size != binary.LittleEndian.Uint64(b[len(b)-24:]) {
		return nil, errors.New("mismatched ASv2 size markers")
	}

	return b[:len(b)-24], nil
}

func (z *Zip) InjectBeforeCD(data []byte) error {
	name := z.file.Name() + "-signed"
	z.file.Seek(0, 0)
	all, err := ioutil.ReadAll(z.file)
	if err != nil {
		return err
	}
	outf, err := os.Create(name)
	if err != nil {
		return err
	}
	defer outf.Close()
	binary.LittleEndian.PutUint32(all[z.eocdOffset+16:], uint32(len(data))+uint32(z.cdOffset))
	outf.Write(all[:z.cdOffset])
	outf.Write(data)
	outf.Write(all[z.cdOffset:])
	return nil
}

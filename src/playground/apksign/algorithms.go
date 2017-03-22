package apksign

func IDtoString(id uint32) string {
	switch id {
	case 0x0101:
		return "RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc"
	case 0x0102:
		return "RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc"
	case 0x0103:
		return "RSASSA-PKCS1-v1_5 with SHA2-256 digest."
	case 0x0104:
		return "RSASSA-PKCS1-v1_5 with SHA2-512 digest."
	case 0x0201:
		return "ECDSA with SHA2-256 digest"
	case 0x0202:
		return "ECDSA with SHA2-512 digest"
	case 0x0301:
		return "DSA with SHA2-256 digest"
	default:
		return "unknown algorithm"
	}
}

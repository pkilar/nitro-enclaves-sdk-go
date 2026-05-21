package cms

import "encoding/asn1"

// OIDs (must be var because asn1.ObjectIdentifier is a slice and cannot be const).
var (
	OIDData                         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDEnvelopedData                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OIDEncryptionAlgorithmRSAESOAEP = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	OIDEncryptionAlgorithmAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

const (
	EnvelopedDataVersion              = 2
	EnvelopedDataRecipientInfoVersion = 2
)

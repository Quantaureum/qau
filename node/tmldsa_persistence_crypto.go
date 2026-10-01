// Quantaureum Node source, version 1.0.0.
package node

import "github.com/quantaureum/qau/wallet/tss"

var (
	thresholdEncryptPersistenceBlob = tss.EncryptSingleShareBlob
	thresholdDecryptPersistenceBlob = tss.DecryptSingleShareBlob
	tmldsaEncryptPersistenceBlob    = thresholdEncryptPersistenceBlob
	tmldsaDecryptPersistenceBlob    = thresholdDecryptPersistenceBlob
)

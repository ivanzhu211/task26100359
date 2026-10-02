package keyvault

import "errors"

var errWeakKDF = errors.New("keyvault: kdf iteration count too low")

// ErrBadPassphrase is returned by Open when the passphrase does not match.
var ErrBadPassphrase = errors.New("keyvault: bad passphrase")

//go:build fips

package crypto

func deriveKeyArgon2id(password, salt []byte, params KDFParams) ([]byte, error) {
	return nil, ErrAlgorithmNotApproved
}

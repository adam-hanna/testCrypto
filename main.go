/*
 *
 * This code uses helper functions from dgrijalva/jwt-go
 * https://github.com/dgrijalva/jwt-go
 *
 */

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
)

var (
	ErrKeyMustBePEMEncoded = errors.New("Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key")
	ErrNotRSAPrivateKey    = errors.New("Key is not a valid RSA private key")
	ErrNotRSAPublicKey     = errors.New("Key is not a valid RSA public key")
	ErrInvalidKey          = errors.New("key is invalid")
	ErrInvalidKeyType      = errors.New("key is of invalid type")
	ErrHashUnavailable     = errors.New("the requested hash function is unavailable")
	ErrNotECPublicKey      = errors.New("Key is not a valid ECDSA public key")
	ErrNotECPrivateKey     = errors.New("Key is not a valid ECDSA private key")
)

// Implements the RSA family of signing methods signing methods
type SigningMethodRSA struct {
	Name string
	Hash crypto.Hash
}

// Implements the RSAPSS family of signing methods signing methods
type SigningMethodRSAPSS struct {
	*SigningMethodRSA
	Options *rsa.PSSOptions
}

func main() {
	// Generate RSA Keys
	rsaPrivateBytes, err := ioutil.ReadFile("app.rsa")
	if err != nil {
		fmt.Println(err)
		return
	}

	rsaPrivateKey, err := ParseRSAPrivateKeyFromPEM(rsaPrivateBytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	rsaPublicBytes, err := ioutil.ReadFile("app.rsa.pub")
	if err != nil {
		fmt.Println(err)
		return
	}

	rsaPublicKey, err := ParseRSAPublicKeyFromPEM(rsaPublicBytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Generate ECDSA Keys
	ecdsaPrivateBytes, err := ioutil.ReadFile("priv_ecdsa.pem")
	if err != nil {
		fmt.Println(err)
		return
	}

	ecdsaPrivateKey, err := ParseECPrivateKeyFromPEM(ecdsaPrivateBytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	ecdsaPublicBytes, err := ioutil.ReadFile("pub_ecdsa.pem")
	if err != nil {
		fmt.Println(err)
		return
	}

	ecdsaPublicKey, err := ParseECPublicKeyFromPEM(ecdsaPublicBytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	hmacKey := generateSessionId()
	hmacKeyBytes := []byte(hmacKey)

	doRSA(rsaPrivateKey, rsaPublicKey)
	doECDSA(ecdsaPrivateKey, ecdsaPublicKey)
	doHMAC(&hmacKeyBytes)
}

// Parse PEM encoded PKCS1 or PKCS8 private key
func ParseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, ErrNotRSAPrivateKey
	}

	return pkey, nil
}

// Parse PEM encoded PKCS1 or PKCS8 public key
func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, ErrNotRSAPublicKey
	}

	return pkey, nil
}

func generateSessionId() string {
	b := make([]byte, 128)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

func doRSA(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) {
	// SignPSS
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthEqualsHash
	opts.Hash = crypto.SHA512

	sessionID := generateSessionId()
	if flag.Lookup("test.v") == nil {
		fmt.Printf("The session id: %s\n", sessionID)
	}

	PSSmessage := []byte(sessionID)
	pssh := opts.Hash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)
	if flag.Lookup("test.v") == nil {
		fmt.Printf("PSS hashed: %x\n", hashed)
	}

	signaturePSS, err := signRSA(privateKey, &opts.Hash, &hashed, &opts)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if flag.Lookup("test.v") == nil {
		fmt.Printf("PSS Signature : %x\n", signaturePSS)
	}

	// VerifyPSS
	err = verifyRSA(publicKey, &opts.Hash, &hashed, &signaturePSS, &opts)

	if err != nil {
		if flag.Lookup("test.v") == nil {
			fmt.Println("VerifyPSS failed")
		}
		os.Exit(1)
	} else {
		if flag.Lookup("test.v") == nil {
			fmt.Println("VerifyPSS successful")
		}
	}
}

func signRSA(privateKey *rsa.PrivateKey, hash *crypto.Hash, hashed *[]byte, opts *rsa.PSSOptions) ([]byte, error) {
	return rsa.SignPSS(rand.Reader, privateKey, *hash, *hashed, opts)
}

func verifyRSA(publicKey *rsa.PublicKey, hash *crypto.Hash, hashed *[]byte, signaturePSS *[]byte, opts *rsa.PSSOptions) error {
	return rsa.VerifyPSS(publicKey, *hash, *hashed, *signaturePSS, opts)
}

func doECDSA(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) {
	// SignECDSA
	hash := crypto.SHA512

	sessionID := generateSessionId()
	if flag.Lookup("test.v") == nil {
		fmt.Printf("The session id: %s\n", sessionID)
	}

	ECDSAmessage := []byte(sessionID)
	pssh := hash.New()
	pssh.Write(ECDSAmessage)
	hashed := pssh.Sum(nil)
	if flag.Lookup("test.v") == nil {
		fmt.Printf("ECDSA hashed: %x\n", hashed)
	}

	r, s, err := signECDSA(privateKey, &hashed)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	if flag.Lookup("test.v") == nil {
		fmt.Printf("Signature : %x\n", signature)
	}

	// VerifyECDSA
	verified := verifyECDSA(publicKey, &hashed, r, s)

	if !verified {
		if flag.Lookup("test.v") == nil {
			fmt.Println("VerifyECDSA failed")
		}
		os.Exit(1)
	} else {
		if flag.Lookup("test.v") == nil {
			fmt.Println("VerifyECDSA successful")
		}
	}
}

func signECDSA(privateKey *ecdsa.PrivateKey, hashed *[]byte) (*big.Int, *big.Int, error) {
	return ecdsa.Sign(rand.Reader, privateKey, *hashed)
}

func verifyECDSA(publicKey *ecdsa.PublicKey, hashed *[]byte, r, s *big.Int) bool {
	return ecdsa.Verify(publicKey, *hashed, r, s)
}

// Parse PEM encoded Elliptic Curve Private Key Structure
func ParseECPrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
		return nil, err
	}

	var pkey *ecdsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
		return nil, ErrNotECPrivateKey
	}

	return pkey, nil
}

// Parse PEM encoded PKCS1 or PKCS8 public key
func ParseECPublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *ecdsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
		return nil, ErrNotECPublicKey
	}

	return pkey, nil
}

func doHMAC(key *[]byte) {
	sessionID := generateSessionId()
	sessionIDBytes := []byte(sessionID)

	expectedMAC := signHMAC(&sessionIDBytes, key)
	if flag.Lookup("test.v") == nil {
		fmt.Printf("Expected MAC: %x\n", expectedMAC)
	}

	equals := verifyHMAC(&sessionIDBytes, &expectedMAC, key)
	if !equals {
		if flag.Lookup("test.v") == nil {
			fmt.Println("VerifyHMAC failed")
		}
		os.Exit(1)
	} else {
		if flag.Lookup("test.v") == nil {
			fmt.Println("VerifyHMAC successful")
		}
	}
}

func signHMAC(message, key *[]byte) []byte {
	mac := hmac.New(sha512.New, *key)
	mac.Write(*message)
	return mac.Sum(nil)
}

func verifyHMAC(message, messageMAC, key *[]byte) bool {
	mac := hmac.New(sha512.New, *key)
	mac.Write(*message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(*messageMAC, expectedMAC)
}

// 2048
// 8960b8b2787a6d07eb27844b66a9b015bd69493358b2a1e2f8ae81605d9be51f2e88e86e2079eb3f82c711d860f48462466aaca5e7353d95d19576bb9109e2b9951e94f40fa82041000cfbb7382fa328608dbe1417416a8739e4c7de913424bb15763b8bad93de39310faf8fac90f39c74a3b9edb9511105dcc570991d82be95ecfc3484dc9c86a3d76770f9b22aa8eaa30da8d073e2eae042b6c690e7a3b0c2315629d32485c0696ae765e90c13fb7da120ca5803aa7a0c80c7de6884ebb850082d5a1ad2c9f70d283d8804f829b24a23912e8fcdb4bffd3eb2c7138d7c7b0077f3765cc8872656b4fa9eb7a3b0effdaf1b6c1e25fb4a5b0bd10c5053bb7301
// 4096
// 0d2089fbb1775034235b6554c500d27b77bd02ebe525feef8bc2c440c51fe1ef8e4e1eda60962c6641909733b7ffc88f31cf9afc8fb1c11b43e38320e1ceaefc39c81e8c40210ac235f49c252c64f5131a5d8e2d07163bd37bcdb7951f286e7c419e03d6599ba4584060f8bdca3e4f3aef4b9d7295647659d3aad1600a36e8402d950ff7a4299aec6c805848e893711c41e3fa70bae6e5d60d81f07ae876b7aa9d69ec884152eee56231619bdc31fdcd777fd4fd524406d053d51e3bf1f78aef1135148e6ef09c3e5af1edf9d339dcb61937f1df301e28b155a4be51b8ca1be50349d0e36e2c30c48ae81438db89b1a344f78f32f8a018f4e058aa23f8c3410eb752791fbe285bffcd3ecca7b908a9df7cb145f2ade13a01ed2e41ae8108136592e4f8d675d4f39cdc488063ef74c6a010d283c4d24b1ae59633d07cd11643ea1110ba564384f34f76966db1becb157941d446b65aa3def9c8d3119091b2fa7791d2c848aeb4dc4aa08538ee0e7b0c6088d403834bf4391c133ee4ce350d4e4ffe110ae358d890742051da463a51f2c0df27ff3345bc82077c78d6b7c8a597756807b1c46a3536b1f92c3cb054305621af65391bb1ce1a05186e8462ca18cc42404344a3d68614e083f653e0768cdaa417d8f5bf5878d9ab9d3d56690d3b029f8bbb4789faff314fb1d3fbff7946ccf35ae4298c99879edc947b24e0035655a6
// go-oauth2-server
// MTQ5Mjk5MzE4N3xEdi1CQkFFQ180SUFBUkFCRUFBQV80M19nZ0FCQm5OMGNtbHVad3dYQUJWbmIxOXZZWFYwYURKZmMyVnlkbVZ5WDNWelpYSVVLbk5sYzNOcGIyNHVWWE5sY2xObGMzTnBiMjdfaFFNQkFRdFZjMlZ5VTJWemMybHZiZ0hfaGdBQkJBRUlRMnhwWlc1MFNVUUJEQUFCQ0ZWelpYSnVZVzFsQVF3QUFRdEJZMk5sYzNOVWIydGxiZ0VNQUFFTVVtVm1jbVZ6YUZSdmEyVnVBUXdBQUFCd180WnRBUVZtWVhwbE1RRVhZV2hoYm01aFFHRnNkVzF1YVM1dGFXNWxjeTVsWkhVQkpEVXhabVF4TXpoaUxUSTFabVl0TkdZNE15MDVNMkkxTFRVNE56UTFNR0ZtTVRRMk53RWtaR0kxTkRCbU9HSXROMkUxTkMwME5EWXdMVGc1TW1ZdE9ESmlPRGsxWXpRME5qSmxBQT09fIf5pQ3W9kd-tg2OJaG_7vKzPxhvJ7umckirpt9Gm7IP

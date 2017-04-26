package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func BenchmarkRSA(b *testing.B) {
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

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		doRSA(rsaPrivateKey, rsaPublicKey)
	}
}

func BenchmarkSignRSA(b *testing.B) {
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

	// SignPSS
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthEqualsHash
	opts.Hash = crypto.SHA512

	sessionID := generateSessionId()

	PSSmessage := []byte(sessionID)
	pssh := opts.Hash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// SignPSS
		_, _ = signRSA(rsaPrivateKey, &opts.Hash, &hashed, &opts)
	}
}

func BenchmarkVerifyRSA(b *testing.B) {
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

	// SignPSS
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthEqualsHash
	opts.Hash = crypto.SHA512

	sessionID := generateSessionId()

	PSSmessage := []byte(sessionID)
	pssh := opts.Hash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	signaturePSS, err := rsa.SignPSS(rand.Reader, rsaPrivateKey, opts.Hash, hashed, &opts)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// VerifyPSS
		_ = verifyRSA(rsaPublicKey, &opts.Hash, &hashed, &signaturePSS, &opts)
	}
}

func BenchmarkECDSA(b *testing.B) {
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

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		doECDSA(ecdsaPrivateKey, ecdsaPublicKey)
	}
}

func BenchmarkSignECDSA(b *testing.B) {
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

	// SignECDSA
	hash := crypto.SHA512

	sessionID := generateSessionId()

	ECDSAmessage := []byte(sessionID)
	pssh := hash.New()
	pssh.Write(ECDSAmessage)
	hashed := pssh.Sum(nil)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// SignECDSA
		_, _, _ = signECDSA(ecdsaPrivateKey, &hashed)
	}
}

func BenchmarkVerifyECDSA(b *testing.B) {
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

	// SignECDSA
	hash := crypto.SHA512

	sessionID := generateSessionId()

	ECDSAmessage := []byte(sessionID)
	pssh := hash.New()
	pssh.Write(ECDSAmessage)
	hashed := pssh.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, ecdsaPrivateKey, hashed)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// VerifyECDSA
		_ = verifyECDSA(ecdsaPublicKey, &hashed, r, s)
	}
}

func BenchmarkHMAC(b *testing.B) {
	// Generate HMAC Key
	hmacKey := generateSessionId()
	hmacKeyBytes := []byte(hmacKey)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		doHMAC(&hmacKeyBytes)
	}
}

func BenchmarkSignHMAC(b *testing.B) {
	// Generate HMAC Key
	hmacKey := generateSessionId()
	hmacKeyBytes := []byte(hmacKey)

	sessionID := generateSessionId()
	sessionIDBytes := []byte(sessionID)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = signHMAC(&sessionIDBytes, &hmacKeyBytes)
	}
}

func BenchmarkVerifyHMAC(b *testing.B) {
	// Generate HMAC Key
	hmacKey := generateSessionId()
	hmacKeyBytes := []byte(hmacKey)

	sessionID := generateSessionId()
	sessionIDBytes := []byte(sessionID)

	mac := hmac.New(sha512.New, hmacKeyBytes)
	mac.Write([]byte(sessionID))
	expectedMAC := mac.Sum(nil)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = verifyHMAC(&sessionIDBytes, &expectedMAC, &hmacKeyBytes)
	}
}

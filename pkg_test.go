package hmac

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func Test_GenerateInvalid_GivesError(t *testing.T) {

	input := []byte("test")
	signature := "ab"
	secretKey := "key"
	err := Validate(input, signature, secretKey)
	if err == nil {
		t.Errorf("expected error when signature didn't have at least 5 characters in length")
		t.Fail()
		return
	}

	wantErr := "valid hash prefixes: [sha1=, sha256=], got: ab"
	if err.Error() != wantErr {
		t.Errorf("want: %s, got: %s", wantErr, err.Error())
		t.Fail()
	}
}

func Test_ValidateWithoutSha1PrefixFails(t *testing.T) {
	digest := "sign this message"
	key := "my key"

	encodedHash := "6791a762f7568f945c2e1e396cea243e944100a6"

	valid := Validate([]byte(digest), encodedHash, key)

	if valid == nil {
		t.Errorf("Expected error due to missing prefix")
		t.Fail()
	}
}

func Test_ValidateWithSha1Prefix(t *testing.T) {
	digest := "sign this message"
	key := "my key"

	encodedHash := "sha1=" + "6791a762f7568f945c2e1e396cea243e944100a6"

	valid := Validate([]byte(digest), encodedHash, key)

	if valid != nil {
		t.Errorf("Expected no error, but got: %s", valid.Error())
		t.Fail()
	}
}

func Test_SignWithKey(t *testing.T) {
	digest := "sign this message"
	key := []byte("my key")

	wantHash := "6791a762f7568f945c2e1e396cea243e944100a6"

	hash := Sign([]byte(digest), key, sha1.New)
	encodedHash := hex.EncodeToString(hash)

	if encodedHash != wantHash {
		t.Errorf("Sign want hash: %s, got: %s", wantHash, encodedHash)
		t.Fail()
	}
}

func Test_SignWithKey_SHA256(t *testing.T) {
	digest := "sign this message"
	key := []byte("my key")

	wantHash := "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7"

	hash := Sign([]byte(digest), key, sha256.New)
	encodedHash := hex.EncodeToString(hash)

	if encodedHash != wantHash {
		t.Errorf("Sign want hash: %s, got: %s", wantHash, encodedHash)
		t.Fail()
	}
}

func Test_ValidateWithSha256Prefix(t *testing.T) {
	digest := "sign this message"
	key := "my key"

	encodedHash := "sha256=" + "41f8b7712c58dc25be8d30cf25e57739a65f5f2f449b59a42e04da1f191512e7"

	valid := Validate([]byte(digest), encodedHash, key)

	if valid != nil {
		t.Errorf("Expected no error, but got: %s", valid.Error())
		t.Fail()
	}
}

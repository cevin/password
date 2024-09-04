package password

import (
	"testing"
)

func TestBcryptHashAndVerify(t *testing.T) {
	password := "mysecurepassword"
	hasher, err := New(BCRYPT)
	if err != nil {
		t.Fatalf("Failed to create Bcrypt hasher: %v", err)
	}

	hash, err := hasher.Hash(password)

	if err != nil {
		t.Fatalf("Failed to hash password with Bcrypt: %v", err)
	}

	match, err := hasher.Verify(hash, password)
	if err != nil {
		t.Fatalf("Failed to verify Bcrypt hash: %v", err)
	}

	if !match {
		t.Error("Bcrypt hash verification failed for the correct password")
	}

	match, err = hasher.Verify(hash, "wrongpassword")
	if err != nil {
		t.Fatalf("Failed to verify Bcrypt hash with wrong password: %v", err)
	}

	if match {
		t.Error("Bcrypt hash verification succeeded for the wrong password")
	}
}

func TestArgon2IHashAndVerify(t *testing.T) {
	password := "mysecurepassword"
	hasher, err := New(ARGON2I)
	if err != nil {
		t.Fatalf("Failed to create Argon2I hasher: %v", err)
	}

	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Failed to hash password with Argon2I: %v", err)
	}

	match, err := hasher.Verify(hash, password)
	if err != nil {
		t.Fatalf("Failed to verify Argon2I hash: %v", err)
	}

	if !match {
		t.Error("Argon2I hash verification failed for the correct password")
	}

	match, err = hasher.Verify(hash, "wrongpassword")
	if err != nil {
		t.Fatalf("Failed to verify Argon2I hash with wrong password: %v", err)
	}

	if match {
		t.Error("Argon2I hash verification succeeded for the wrong password")
	}
}

func TestArgon2IDHashAndVerify(t *testing.T) {
	password := "mysecurepassword"
	hasher, err := New(ARGON2ID)
	if err != nil {
		t.Fatalf("Failed to create Argon2ID hasher: %v", err)
	}

	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Failed to hash password with Argon2ID: %v", err)
	}

	match, err := hasher.Verify(hash, password)
	if err != nil {
		t.Fatalf("Failed to verify Argon2ID hash: %v", err)
	}

	if !match {
		t.Error("Argon2ID hash verification failed for the correct password")
	}

	match, err = hasher.Verify(hash, "wrongpassword")
	if err != nil {
		t.Fatalf("Failed to verify Argon2ID hash with wrong password: %v", err)
	}

	if match {
		t.Error("Argon2ID hash verification succeeded for the wrong password")
	}
}

func TestCustomBcryptCost(t *testing.T) {
	password := "mysecurepassword"
	hasher, err := New(BCRYPT, CostOption{Cost: 10})
	if err != nil {
		t.Fatalf("Failed to create Bcrypt hasher with custom cost: %v", err)
	}

	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Failed to hash password with Bcrypt and custom cost: %v", err)
	}

	match, err := hasher.Verify(hash, password)
	if err != nil {
		t.Fatalf("Failed to verify Bcrypt hash with custom cost: %v", err)
	}

	if !match {
		t.Error("Bcrypt hash verification failed for the correct password with custom cost")
	}
}

func TestCustomArgon2Params(t *testing.T) {
	password := "mysecurepassword"
	argon2Params := Argon2Option{
		Time:    2,
		Memory:  128 * 1024,
		Threads: 4,
		KeyLen:  32,
		SaltLen: 16,
	}
	hasher, err := New(ARGON2ID, argon2Params)
	if err != nil {
		t.Fatalf("Failed to create Argon2ID hasher with custom params: %v", err)
	}

	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Failed to hash password with Argon2ID and custom params: %v", err)
	}

	match, err := hasher.Verify(hash, password)
	if err != nil {
		t.Fatalf("Failed to verify Argon2ID hash with custom params: %v", err)
	}

	if !match {
		t.Error("Argon2ID hash verification failed for the correct password with custom params")
	}
}

package password

import (
	_md5 "crypto/md5"
	_sha1 "crypto/sha1"
	"errors"
	"fmt"
	_bcrypt "golang.org/x/crypto/bcrypt"
)

var UnsupportedAlgorithm = errors.New("unsupported algorithm")

type Algorithm interface {
	Encode(password string) (string, error)
	Verify(password string, hash string) (bool, error)
}

type MD5 struct{}

func (md5 MD5) Encode(password string) (string, error) {
	return fmt.Sprintf("%x", _md5.Sum([]byte(password))), nil
}
func (md5 MD5) Verify(password string, hash string) (bool, error) {
	hex, _ := md5.Encode(password)
	return hex == hash, nil
}

type SHA1 struct{}

func (sha1 SHA1) Encode(password string) (string, error) {
	return fmt.Sprintf("%x", _sha1.Sum([]byte(password))), nil
}
func (sha1 SHA1) Verify(password string, hash string) (bool, error) {
	hex, _ := sha1.Encode(password)
	return hex == hash, nil
}

type Bcrypt struct{}

func (bcrypt Bcrypt) Encode(password string) (hashed string, err error) {
	ret, err := _bcrypt.GenerateFromPassword([]byte(password), 11)
	return fmt.Sprintf("%s", ret), err
}
func (bcrypt Bcrypt) Verify(password string, hash string) (bool, error) {
	err := _bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil, err
}

func NewAlgo(algo string) (Algorithm, error) {
	switch algo {
	case "md5":
		return MD5{}, nil
	case "sha1":
		return SHA1{}, nil
	case "bcrypt":
		return Bcrypt{}, nil
	default:
		return nil, UnsupportedAlgorithm
	}
}

package password

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"strings"
)

type AlgoName string

const (
	BCRYPT   AlgoName = "bcrypt"
	ARGON2I  AlgoName = "argon2i"
	ARGON2ID AlgoName = "argon2id"
)

// Params 接口，用于表示不同算法的参数
type Params interface{}

// BcryptParams 包含 bcrypt 的参数
type BcryptParams struct {
	Cost int
}

// Argon2Params 包含 Argon2 算法的参数
type Argon2Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

func (params *Argon2Params) validate() {
	if params.KeyLen == 0 {
		params.KeyLen = DefaultArgon2Params.KeyLen
	}
	if params.SaltLen == 0 {
		params.SaltLen = DefaultArgon2Params.SaltLen
	}
}

// Option 接口用于修改 Params
type Option interface {
	Apply(Params)
}

// CostOption 实现 Option 接口，用于设置 cost 参数
type CostOption struct {
	Cost int
}

func (o CostOption) Apply(params Params) {
	if p, ok := params.(*BcryptParams); ok {
		p.Cost = o.Cost
	}
}

// Argon2Option 用于设置 Argon2 参数
type Argon2Option struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

func (o Argon2Option) Apply(params Params) {
	if p, ok := params.(*Argon2Params); ok {
		p.Time = o.Time
		p.Memory = o.Memory
		p.Threads = o.Threads
		p.KeyLen = o.KeyLen
		p.SaltLen = o.SaltLen
	}
}

var DefaultBcryptParams = BcryptParams{Cost: 12}
var DefaultArgon2Params = Argon2Params{
	Time:    2,
	Memory:  64 * 1024,
	Threads: 4,
	KeyLen:  32,
	SaltLen: 16,
}

// New 用于创建指定算法的 Password 实现
func New(algo AlgoName, options ...Option) (Password, error) {
	var params Params
	switch algo {
	case BCRYPT:
		params = &DefaultBcryptParams
	case ARGON2I, ARGON2ID:
		params = &DefaultArgon2Params
		params.(*Argon2Params).validate()
	default:
		return nil, errors.New("unsupported algorithm")
	}

	for _, option := range options {
		option.Apply(params)
	}

	switch algo {
	case BCRYPT:
		return Bcrypt{Params: *params.(*BcryptParams)}, nil
	case ARGON2I:
		return Argon2I{Params: *params.(*Argon2Params)}, nil
	case ARGON2ID:
		return Argon2ID{Params: *params.(*Argon2Params)}, nil
	default:
		return nil, errors.New("unsupported algorithm")
	}
}

type Password interface {
	Hash(password string) (string, error)
	Verify(hash string, password string) (bool, error)
}

type Bcrypt struct {
	Params BcryptParams
}

func (b Bcrypt) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), b.Params.Cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (b Bcrypt) Verify(hash string, password string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return false, err
	}
	return true, nil
}

type Argon2I struct {
	Params Argon2Params
}

func (a Argon2I) Hash(password string) (string, error) {
	salt, err := generateSalt(a.Params.SaltLen)
	if err != nil {
		return "", err
	}
	hash := argon2.Key([]byte(password), salt, a.Params.Time, a.Params.Memory, a.Params.Threads, a.Params.KeyLen)
	return formatArgon2Hash(ARGON2I, a.Params, hash, salt), nil
}

func (a Argon2I) Verify(hash string, password string) (bool, error) {
	salt, extractedHash, params, err := parseArgon2Hash(hash)
	if err != nil {
		return false, err
	}
	newHash := argon2.Key([]byte(password), salt, params.Time, params.Memory, params.Threads, a.Params.KeyLen)
	return compareHashes(newHash, extractedHash), nil
}

type Argon2ID struct {
	Params Argon2Params
}

func (a Argon2ID) Hash(password string) (string, error) {
	salt, err := generateSalt(a.Params.SaltLen)
	if err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, a.Params.Time, a.Params.Memory, a.Params.Threads, a.Params.KeyLen)
	return formatArgon2Hash(ARGON2ID, a.Params, hash, salt), nil
}

func (a Argon2ID) Verify(hash string, password string) (bool, error) {
	salt, extractedHash, params, err := parseArgon2Hash(hash)
	if err != nil {
		return false, err
	}
	newHash := argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, params.KeyLen)
	return compareHashes(newHash, extractedHash), nil
}

// Helpers

func generateSalt(length uint32) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func formatArgon2Hash(algo AlgoName, params Argon2Params, hash, salt []byte) string {
	return fmt.Sprintf("$%s$v=19$m=%d,t=%d,p=%d$%s$%s",
		algo,
		params.Memory,
		params.Time,
		params.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

func parseArgon2Hash(hash string) ([]byte, []byte, Argon2Params, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return nil, nil, Argon2Params{}, errors.New("invalid hash format")
	}

	params := DefaultArgon2Params
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Time, &params.Threads)
	if err != nil {
		return nil, nil, Argon2Params{}, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, Argon2Params{}, err
	}

	extractedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, Argon2Params{}, err
	}

	return salt, extractedHash, params, nil
}

func compareHashes(hash1, hash2 []byte) bool {
	return strings.Compare(string(hash1), string(hash2)) == 0
}

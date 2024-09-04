package main

import (
	"fmt"
	"github.com/cevin/password"
)

func main() {
	pwd := "testpassword"

	hasher, err := password.New(password.ARGON2ID)

	if err != nil {
		panic(err)
	}

	hash, err := hasher.Hash(pwd)
	if err != nil {
		panic(err)
	}

	fmt.Println(hash)

}

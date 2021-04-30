package main

import (
	"github.cicd.cloud.fpdev.io/BD/fp-csg-snetinel/cmd"
)

var encryptionKey string

func main() {
	cmd.Execute(encryptionKey)
}

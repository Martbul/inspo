package main

import (
	"fmt"
	"net/http"
	"time"
)

const cookieFliemane = ".cookie"

var (
	version  string = "1.0.0"
	commitID string = "dev"
)

func main() {
	defer os.Exit(0)

	semver := fmt.Sprintf("%s+%s", version, commitID)

	http.DefaultClient.Timeout = 1500 * time.Millisecond

	tmpLogger := serv
}

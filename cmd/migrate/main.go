// Command s3eg-migrate is deprecated. Use s3eg-cli instead.
//
// s3eg-migrate was the offline migration tool for re-encrypting objects
// by accessing the S3 backend directly. This approach has been removed.
// The supported re-encryption path is GET-through-gateway → PUT-through-gateway
// using any standard S3 client (awscli, s5cmd, mc, etc.).
//
// The audit sub-commands (inspect, verify-key, list-algorithm) are available
// via s3eg-cli. See docs/MIGRATION.md for details.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "s3eg-migrate is deprecated; use s3eg-cli instead.")
	fmt.Fprintln(os.Stderr, "For re-encryption use GET-through-gateway -> PUT-through-gateway.")
	fmt.Fprintln(os.Stderr, "See docs/MIGRATION.md for details.")
	os.Exit(1)
}

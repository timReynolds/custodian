package e2e_test

import (
	"flag"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() && os.Getenv("CUSTODIAN_TEST_FORCE_E2E") != "1" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

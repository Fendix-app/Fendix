//go:build !unix

package secrets

import "testing"

func extraNonRegular(t *testing.T, root string) {}

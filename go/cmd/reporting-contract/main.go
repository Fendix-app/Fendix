package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Fendix-app/Fendix/go/internal/catalog"
)

func main() {
	schemaPath := flag.String("schema", "../docs/schema.json", "path to the authoritative JSON report schema")
	out := flag.String("out", "", "write the contract to this path (stdout when empty)")
	flag.Parse()
	schema, err := os.ReadFile(*schemaPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	contract, err := catalog.BuildReporting(schema)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	data, err := json.MarshalIndent(contract, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	data = append(data, '\n')
	if *out == "" {
		_, err = os.Stdout.Write(data)
	} else {
		err = os.WriteFile(*out, data, 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

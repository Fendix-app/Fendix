package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Abdel-RahmanSaied/Fendix/internal/catalog"
)

func main() {
	out := flag.String("out", "", "write the contract to this path (stdout when empty)")
	flag.Parse()
	contract, err := catalog.Build()
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

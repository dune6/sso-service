package main

import (
	"fmt"
	"github.com/dune6/sso-auth/internal/config"
)

func main() {
	cfg := config.MustLoad()
	fmt.Printf("%+v\n", cfg)
}

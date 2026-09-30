package main

import (
	"fmt"
	"net/http"
	"os"

	handler "github.com/hirotomasato/paygateme/api"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("🚀 Crave Payment Gateway running on http://localhost:%s\n", port)
	if err := http.ListenAndServe(":"+port, http.HandlerFunc(handler.Handler)); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
	}
}

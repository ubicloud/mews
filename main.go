package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	configFile := flag.String("config", "mews.yaml", "Path to configuration file")
	port := flag.String("port", "6189", "Port to listen on (always binds to localhost)")
	flag.Parse()

	cfg, err := LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	listenAddr := "localhost:" + *port

	log.Printf("Loaded configuration:")
	log.Printf("  Listen address: %s", listenAddr)
	log.Printf("  Bastion sets: %d", len(cfg.BastionSets))
	for name, bastions := range cfg.BastionSets {
		log.Printf("    %s: %d bastions", name, len(bastions))
	}
	log.Printf("  Upstreams: %d", len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		log.Printf("    %s -> %s (bastion_set: %s)", u.Local, u.Remote, u.BastionSet)
	}

	server := NewServer(cfg, *port)
	defer server.Close()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		server.Close()
		os.Exit(0)
	}()

	log.Printf("Starting proxy server on http://%s", listenAddr)
	if err := http.ListenAndServe(listenAddr, server); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var (
	ConnPort = flag.Int("port", 4568, "Sets the port to listen on.")
	ConnHost = flag.String("host", "localhost", "Sets the host to listen on.")
)

func main() {
	go runListener()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Press ctrl+c to shutdown")
	<- c
	fmt.Println("ctrl+c detected. Shutting down")
}

func runListener() {
	flag.Parse()
	// Listen for incoming connections.
	host, port := *ConnHost, *ConnPort
	address := fmt.Sprintf("%s:%d", host, port)
	l, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	// Close the listener when the application closes.
	defer l.Close()
	fmt.Println("Listening on " + address)
	fmt.Println(fmt.Sprintf("[vuln-test] ${jndi:ldap://%v/poc}",address))
	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go handleRequest(conn)
	}
}

// Handles incoming requests.
func handleRequest(conn net.Conn) {
	fmt.Println("[vulnerability]",conn.RemoteAddr())

	// Close the connection immediately
	conn.Close()
}
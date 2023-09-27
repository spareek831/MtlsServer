package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
)

func main() {
	// Create a TLS configuration that requests client certificates
	tlsConfig := &tls.Config{
		//ClientAuth: tls.RequestClientCert,
		ClientAuth: tls.RequireAnyClientCert,
		//GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		//	//certList := info.config.Certificates
		//	//
		//	//if len(certList) > 0 {
		//	//	fmt.Printf("Found something\n")
		//	//	for _, cert := range certList {
		//	//		var certPEM []byte
		//	//		for _, c := range cert.Certificate {
		//	//			block := &pem.Block{
		//	//				Type:  "CERTIFICATE",
		//	//				Bytes: c,
		//	//			}
		//	//			certPEM = append(certPEM, pem.EncodeToMemory(block)...)
		//	//		}
		//	//		fmt.Println("-----begin cert-----")
		//	//		fmt.Println(string(certPEM))
		//	//		fmt.Println("-----end cert-----")
		//	//	}
		//
		//	//}
		//	return nil, nil
		//},

		// Provide server certificate over here
		Certificates: []tls.Certificate{},
	}

	// Create an HTTP server with custom handler
	server := &http.Server{
		Addr:      ":6969",
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(handleRequest),
	}

	//http.HandleFunc("/hello", getHello)

	fmt.Println("Server is listening on :6969...")
	err := server.ListenAndServeTLS("server.crt", "server.key")
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
}

func getHello(w http.ResponseWriter, request *http.Request) {
	fmt.Println("Got /hello request")

	// Check if the client provided a certificate
	if len(request.TLS.PeerCertificates) > 0 {
		// Iterate over the client's certificate chain
		for i, cert := range request.TLS.PeerCertificates {
			fmt.Printf("Certificate %d:\n", i+1)
			fmt.Printf("Subject: %s\n", cert.Subject)
			fmt.Printf("Issuer: %s\n", cert.Issuer)
			fmt.Printf("Serial Number: %s\n", cert.SerialNumber)
			fmt.Println("-----BEGIN CERTIFICATE-----")
			fmt.Println(cert.Raw)
			fmt.Println("-----END CERTIFICATE-----")
		}
	} else {
		fmt.Println("No client certificate provided.")
	}

	a := "hello"
	io.WriteString(w, a)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Extract the client's certificate from the request's TLS connection
	fmt.Printf("Handling request\n")
	certificate, err := extractClientCertificate(r.TLS)
	if err != nil {
		fmt.Println("Failed to extract client certificate")
		http.Error(w, "Failed to extract client certificate", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Got the client certificate")

	fmt.Printf("Subject: %s\n", certificate.Subject)
	fmt.Printf("Issuer: %s\n", certificate.Issuer)
	fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Found certificate"))
}

func extractClientCertificate(tlsConn *tls.ConnectionState) (*x509.Certificate, error) {
	// Check if a client certificate was provided in the TLS handshake
	if len(tlsConn.PeerCertificates) > 0 {
		// The first certificate in the list is the client's certificate
		fmt.Println("FOUND A CERT")
		//fmt.Println(tlsConn.PeerCertificates[0])
		return tlsConn.PeerCertificates[0], nil
	}
	return nil, fmt.Errorf("Client certificate not provided")
}

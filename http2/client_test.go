package http2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/invisv-privacy/masque/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/net/http2"
)

const h2oServiceName string = "h2o"

var logger *slog.Logger
var containerGateway string
var stack tc.ComposeStack

func TestMain(m *testing.M) {
	level := slog.LevelDebug
	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	// Start the h2o docker container
	identifier := tc.StackIdentifier("h2o_test")
	composeFile := fmt.Sprintf("%s/docker-compose.yml", testutils.RootDir())
	compose, err := tc.NewDockerComposeWith(tc.WithStackFiles(composeFile), identifier)
	if err != nil {
		log.Fatalf("error in NewDockerComposeAPIWith: %v", err)
	}

	defer func() {
		if err := compose.Down(
			context.Background(),
			tc.RemoveOrphans(true),
			tc.RemoveImagesLocal,
		); err != nil {
			log.Fatalf("error in compose.Down: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stack = compose.WaitForService(h2oServiceName,
		// The h2o conf provides a /status endpoint listening on
		// non-TLS port 8081
		wait.
			NewHTTPStrategy("/status").
			WithPort("8081/tcp").
			WithStartupTimeout(10*time.Second),
	)

	if err := stack.Up(ctx, tc.Wait(true), tc.RunServices("h2o")); err != nil {
		log.Fatalf("error in compose.Up(): %v", err)
	}

	container, err := stack.ServiceContainer(ctx, h2oServiceName)
	if err != nil {
		log.Fatalf("error in stack.ServiceContainer: %v", err)
	}

	logger.Info("compose up", "services", stack.Services(), "container", container)

	// Kind of awkward network info parsing here.
	// We need the container's gateway IP because that _should_ be the address the host can ListenUDP on where the container can access it.
	containerIPs, err := container.ContainerIPs(ctx)
	if err != nil {
		log.Fatalf("error in container.ContainerIPs: %v", err)
	}

	containerIP := containerIPs[0]
	containerIPSplit := strings.Split(containerIP, ".")
	containerNet := strings.Join(containerIPSplit[:len(containerIPSplit)-1], ".")

	containerGateway = fmt.Sprintf("%v.1", containerNet)

	m.Run()
}

func TestCreateTCPStream(t *testing.T) {
	level := slog.LevelDebug
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	// Start target HTTP/S server
	expectedResponse := "test http response data"
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "", r.Header.Get("Proxy-Authorization"), "Should not pass the auth token to the end target server")
		assert.Equal(t, http.MethodGet, r.Method, "Request to the end target server should be a GET")
		_, err := fmt.Fprintf(w, expectedResponse)
		require.NoError(t, err, "fmt.Fprintf")
	}))
	ts.EnableHTTP2 = true
	// We want to listen on 0.0.0.0 because the proxy container will be on a different non-localhost network.
	// In order to do that we have this kind of awkward hack borrowed from:
	// https://stackoverflow.com/a/42218765/1787596
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		log.Fatal(err)
	}

	// Swap out the default test server listener with our custom one listening on 0.0.0.0
	require.NoError(t, ts.Listener.Close(), "ts.Listener.Close()")
	ts.Listener = l
	ts.StartTLS()
	defer ts.Close()

	log.Printf("Test server listening on: %v", ts.URL)

	urlSplit := strings.Split(ts.URL, ":")
	port := urlSplit[len(urlSplit)-1]

	// Now configure and start the MASQUE client
	certDataFile := fmt.Sprintf("%s/testdata/h2o/server.crt", testutils.RootDir())
	certData, err := os.ReadFile(certDataFile)
	require.NoError(t, err, "Reading certData")

	config := ClientConfig{
		ProxyAddr: "localhost:8444",
		// The h2o server we're using doesn't require an actual token so this can be anything
		AuthToken: "fake-token",
		Logger:    logger,
		CertData:  certData,
	}

	c := NewClient(config)

	err = c.ConnectToProxy()
	require.NoError(t, err, "ConnectToProxy")

	dockerHostURL := fmt.Sprintf("%v:%v", containerGateway, port)
	conn, err := c.CreateTCPStream(dockerHostURL)
	require.NoError(t, err, "CreateTCPStream")
	defer func() {
		require.NoError(t, conn.Close(), "conn.Close()")
	}()

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%v", dockerHostURL), nil)
	require.NoError(t, err, "http.NewRequest")

	certpool := x509.NewCertPool()
	certpool.AddCert(ts.Certificate())
	tlsDialWrapper := func(network, addr string, cfg *tls.Config) (net.Conn, error) {
		tlsConf := &tls.Config{
			RootCAs: certpool,
			// It seems as though the httptest TLS server uses this arbitrarily as it's ServerName 🤷
			ServerName: "example.com",
			NextProtos: ts.TLS.NextProtos,
		}
		tlsClient := tls.Client(&testutils.NetConnWrapper{ReadWriteCloser: conn}, tlsConf)
		err = tlsClient.Handshake()
		return tlsClient, err
	}

	transport := &http2.Transport{
		DialTLS: tlsDialWrapper,
	}

	httpClient := http.Client{
		Transport: transport,
	}
	response, err := httpClient.Do(req)
	require.NoError(t, err, "httpClient.Do")

	defer func() {
		require.NoError(t, response.Body.Close(), "response.Body.Close()")
	}()
	data, err := io.ReadAll(response.Body)
	require.NoError(t, err, "io.ReadAll response body")

	log.Printf("got response: %v", response)

	assert.Equal(t, 200, response.StatusCode, "Should receive 200 response")
	assert.Equal(t, expectedResponse, string(data), "Should receive expected body")
}

func TestCreateUDPStream(t *testing.T) {
	expectedRequest := "test udp request data\n"
	expectedResponse := "test udp response data\n"

	// Start target udp server
	// We want to listen on the gateway IP so the proxy container can access it.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(containerGateway)})
	require.NoError(t, err, "net.ListenUDP")

	go func() {
		var buf [512]byte
		n, addr, err := conn.ReadFromUDP(buf[0:])
		require.NoError(t, err, "ReadFromUDP")
		assert.Equal(t, expectedRequest, string(buf[0:n]), "Should receive correct UDP request")

		logger.Info("ReadFromUDP", "buf", buf, "addr", addr)

		// Write back the message over UPD
		_, err = conn.WriteToUDP([]byte(expectedResponse), addr)
		require.NoError(t, err, "conn.WriteToUDP")
	}()

	udpListenAddr := conn.LocalAddr()

	urlSplit := strings.Split(udpListenAddr.String(), ":")
	udpListenPort := urlSplit[len(urlSplit)-1]

	// Now configure and start the MASQUE client
	certDataFile := fmt.Sprintf("%s/testdata/h2o/server.crt", testutils.RootDir())
	certData, err := os.ReadFile(certDataFile)
	require.NoError(t, err, "Reading certData")

	config := ClientConfig{
		ProxyAddr: "localhost:8444",
		// The h2o server we're using doesn't require an actual token so this can be anything
		AuthToken: "fake-token",
		Logger:    logger,
		CertData:  certData,
	}

	c := NewClient(config)

	dockerHostURL := fmt.Sprintf("%v:%v", containerGateway, udpListenPort)

	udpConn, err := c.CreateUDPStream(dockerHostURL)
	require.NoError(t, err, "CreateUDPStream")
	defer func() {
		require.NoError(t, udpConn.Close(), "udpConn.Close()")
	}()

	_, err = udpConn.Write([]byte(expectedRequest))
	require.NoError(t, err, "udpConn.Write")

	var buf [512]byte
	n, err := udpConn.Read(buf[0:])
	require.NoError(t, err, "udpConn.Read")

	assert.Equal(t, expectedResponse, string(buf[0:n]), "Should receive correct UDP response")
	logger.Info("got response", "buf", buf)
}

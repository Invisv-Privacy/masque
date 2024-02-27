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
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/net/http2"
)

const h2oServiceName string = "h2o"

func RootDir() string {
	_, b, _, _ := runtime.Caller(0)
	d := path.Join(path.Dir(b))
	return filepath.Dir(d)
}

type NetConnWrapper struct {
	*Conn
}

func (r *NetConnWrapper) LocalAddr() net.Addr {
	return nil
}

func (r *NetConnWrapper) RemoteAddr() net.Addr {
	return nil
}

func (r *NetConnWrapper) SetDeadline(t time.Time) error {
	return nil
}

func (r *NetConnWrapper) SetReadDeadline(t time.Time) error {
	return nil
}

func (r *NetConnWrapper) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestSimpleClientRequest(t *testing.T) {
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
		fmt.Fprintf(w, expectedResponse)
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
	ts.Listener.Close()
	ts.Listener = l
	ts.StartTLS()
	defer ts.Close()

	log.Printf("Test server listening on: %v", ts.URL)

	urlSplit := strings.Split(ts.URL, ":")
	port := urlSplit[len(urlSplit)-1]

	// Start the h2o docker container
	identifier := tc.StackIdentifier("h2o_test")
	composeFile := fmt.Sprintf("%s/docker-compose.yml", RootDir())
	compose, err := tc.NewDockerComposeWith(tc.WithStackFiles(composeFile), identifier)
	require.NoError(t, err, "NewDockerComposeAPIWith()")

	t.Cleanup(func() {
		require.NoError(t,
			compose.Down(
				context.Background(),
				tc.RemoveOrphans(true),
				tc.RemoveImagesLocal,
			), "compose.Down()")
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stack := compose.WaitForService(h2oServiceName,
		// The h2o conf provides a /status endpoint listening on
		// non-TLS port 8081
		wait.
			NewHTTPStrategy("/status").
			WithPort("8081/tcp").
			WithStartupTimeout(10*time.Second),
	)

	err = stack.Up(ctx, tc.Wait(true))

	require.NoError(t, err, "compose.Up()")

	log.Printf("services: %+v", stack.Services())

	container, err := stack.ServiceContainer(ctx, h2oServiceName)
	require.NoError(t, err, "fetch ServiceContainer")

	log.Printf("container: %+v", container)

	// Now configure and start the MASQUE client
	certDataFile := fmt.Sprintf("%s/testdata/h2o/server.crt", RootDir())
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

	// host.docker.internal is a docker specific host mapping for the h2o container that resolves to our localhost
	dockerHostUrl := fmt.Sprintf("host.docker.internal:%v", port)
	conn, err := c.CreateTCPStream(dockerHostUrl)
	require.NoError(t, err, "CreateTCPStream")
	defer conn.Close()

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%v", dockerHostUrl), nil)
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
		tlsClient := tls.Client(&NetConnWrapper{conn}, tlsConf)
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

	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	require.NoError(t, err, "io.ReadAll response body")

	log.Printf("got response: %v", response)

	assert.Equal(t, 200, response.StatusCode, "Should receive 200 response")
	assert.Equal(t, expectedResponse, string(data), "Should receive expected body")
}

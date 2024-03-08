package http3

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/invisv-privacy/masque/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/wait"
)

const h2oServiceName string = "h2o"

func TestSimpleClientRequest(t *testing.T) {
	level := slog.LevelDebug
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	// Start the h2o docker container
	identifier := tc.StackIdentifier("h2o_test")
	composeFile := fmt.Sprintf("%s/docker-compose.yml", testutils.RootDir())
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

	container, err := stack.ServiceContainer(ctx, h2oServiceName)
	require.NoError(t, err, "fetch ServiceContainer")

	logger.Info("compose up", "services", stack.Services(), "container", container)

	// Kind of awkward network info parsing here.
	// We need the container's gateway IP because that _should_ be the address the host can ListenUDP on where the container can access it.
	containerIPs, err := container.ContainerIPs(ctx)
	require.NoError(t, err, "container.ContainerIPs")

	containerIP := containerIPs[0]
	containerIPSplit := strings.Split(containerIP, ".")
	containerNet := strings.Join(containerIPSplit[:len(containerIPSplit)-1], ".")

	containerGateway := fmt.Sprintf("%v.1", containerNet)

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
		Insecure:  true,
	}

	c, err := NewClient(config)
	defer c.Close()
	require.NoError(t, err, "NewClient")

	dockerHostURL := fmt.Sprintf("%v:%v", containerGateway, udpListenPort)

	udpConn, err := c.CreateUDPStream(dockerHostURL)
	require.NoError(t, err, "CreateUDPStream")
	defer udpConn.Close()

	_, err = udpConn.Write([]byte(expectedRequest))
	require.NoError(t, err, "udpConn.Close")

	var buf [512]byte
	n, err := udpConn.Read(buf[0:])
	require.NoError(t, err, "udpConn.Read")

	assert.Equal(t, expectedResponse, string(buf[0:n]), "Should receive correct UDP response")
	logger.Info("got response", "buf", buf)
}

# An IETF MASQUE implementation in Go

[![PkgGoDev](https://pkg.go.dev/badge/github.com/invisv-privacy/masque)](https://pkg.go.dev/badge/github.com/invisv-privacy/masque)
![Build Status](https://github.com/invisv-privacy/masque/actions/workflows/build.yaml/badge.svg?branch=main)

## What is INVISV masque?

INVISV **masque** is an implementation of the [IETF MASQUE](https://datatracker.ietf.org/wg/masque/about/) tunneling protocol, written in Go. INVISV **masque** provides the client-side functionality needed for running a [Multi-Party Relay](https://invisv.com/articles/relay.html) service to protect users' network privacy.

The IETF MASQUE protocol functions as a generalization of the HTTP CONNECT method, enabling the tunneling of arbitrary traffic via a MASQUE supporting server, via HTTP, to sites on the Internet. Traffic that is tunneled can be of any protocol, meaning that it is often the case that, using IETF MASQUE, there can be multiple encrypted HTTP tunnels nested within one another.

**masque** enables application code on the client to tunnel bytestream (TCP) and packet (UDP) traffic via a MASQUE-supporting proxy, such as the [MASQUE service operated by Fastly](https://www.fastly.com/blog/kicking-off-privacy-week-fastly). Fastly's MASQUE service uses the [h2o](https://github.com/h2o/h2o) webserver, which can be configured as a MASQUE-supporting proxy server for local testing or production use.

## Status

INVISV **masque** has already been in public use in INVISV's [Relay](https://invisv.com/relay/) and [Booth](https://booth.video/) services for over a year. This repository is its first release as an open BSD-licensed codebase.

As of February 2024, this open implementation currently uses HTTP/2 for MASQUE tunneling. With appropriate changes to [quic-go](https://github.com/quic-go/quic-go), which we will be making available in the future, this implementation will also support HTTP/3 for MASQUE tunneling.

## Example application: Relay HTTP Proxy

To demonstrate how to use **masque**, we have included a sample application that presents a standard HTTP proxy interface locally and can used by tools such as `curl` and ordinary web browsers. Traffic sent to the local Relay HTTP proxy is transparently tunneled via MASQUE through the designated proxy server (as authorized by the given proxy authentication token) to the designated website.

To run the relay http proxy:
```
$ go run ./example/relay-http-proxy -token RELAY_TOKEN_HERE -invisvRelay RELAY_SERVER
```
In a new terminal
```
$ curl -v --proxy http://localhost:32190  ipinfo.io/ip
*   Trying 127.0.0.1:32190...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 32190 (#0)
> GET http://ipinfo.io/ip HTTP/1.1
> Host: ipinfo.io
> User-Agent: curl/7.68.0
> Accept: */*
> Proxy-Connection: Keep-Alive
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< server: nginx/1.24.0
< date: Fri, 02 Feb 2024 19:14:08 GMT
< content-type: text/plain; charset=utf-8
< Content-Length: 14
< access-control-allow-origin: *
< x-envoy-upstream-service-time: 1
< via: 1.1 google
< strict-transport-security: max-age=2592000; includeSubDomains
<
* Connection #0 to host localhost left intact
146.75.153.247
```

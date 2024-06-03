# An IETF MASQUE implementation in Go

[![PkgGoDev](https://pkg.go.dev/badge/github.com/invisv-privacy/masque)](https://pkg.go.dev/github.com/invisv-privacy/masque)
![Build Status](https://github.com/invisv-privacy/masque/actions/workflows/build.yaml/badge.svg?branch=main)
[![godocs.io](https://godocs.io/github.com/invisv-privacy/masque?status.svg)](https://godocs.io/github.com/invisv-privacy/masque)

## What is INVISV masque?

INVISV **masque** is an implementation of the [IETF MASQUE](https://datatracker.ietf.org/wg/masque/about/) tunneling protocol, written in Go. INVISV **masque** provides the client-side functionality needed for running a [Multi-Party Relay](https://invisv.com/articles/relay.html) service to protect users' network privacy.

The IETF MASQUE protocol functions as a generalization of the HTTP CONNECT method, enabling the tunneling of arbitrary traffic via a MASQUE supporting server, via HTTP, to sites on the Internet. Traffic that is tunneled can be of any protocol, meaning that it is often the case that, using IETF MASQUE, there can be multiple encrypted HTTP tunnels nested within one another.

**masque** enables application code on the client to tunnel bytestream (TCP) and packet (UDP) traffic via a MASQUE-supporting proxy, such as the [MASQUE service operated by Fastly](https://www.fastly.com/blog/kicking-off-privacy-week-fastly). Fastly's MASQUE service uses the [h2o](https://github.com/h2o/h2o) webserver, which can be configured as a MASQUE-supporting proxy server for local testing or production use.

## Status

INVISV **masque** has already been in public use in INVISV's [Relay](https://invisv.com/relay/) and [Booth](https://booth.video/) services for over a year. This repository is its first release as an open BSD-licensed codebase.

This implementation offers both HTTP/2 and HTTP/3 for MASQUE tunneling.

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

## Example application: Preproxy

In addition to the Relay HTTP Proxy sample application, we have included an application we call the "preproxy". This performs a combination of functions: reverse proxying of inbound traffic and tunneling of that traffic via a (multi-hop) MASQUE tunnel to a given destination. This enables use of unmodified applications with MASQUE tunnels, where the remote client network stack is potentially unaware of the MASQUE tunnel yet wishes to use a MASQUE to reach a destination. See the documentation of preproxy for details.

## Testing

We have automated tests which utilize an h2o container that we can leverage as the MASQUE target.

They can be run by simply using go's test utility:
```
$ go test -v ./...
```

This will automatically spin up the h2o container, configure it as our MASQUE client's proxy target, and then use that for testing.

Because this is all docker/docker-compose based it's trivial to spin up the h2o docker container for manual testing/evaluation.

The h2o service listens on 8081 for http connections and 8444 for https.

First spin up the h2o docker container in the background:
```
$ docker-compose up -d
```

You can check that it's running by querying the `/status` endpoint:
```
$ curl -I http://localhost:8081/status
HTTP/1.1 200 OK
Connection: keep-alive
Content-Length: 6049
Server: h2o/2.3.0-DEV@123f5e2b6
cache-control: no-cache
content-type: text/html; charset=utf-8
last-modified: Tue, 20 Feb 2024 01:02:58 GMT
etag: "65d3fa42-17a1"
accept-ranges: bytes

$ curl --cacert ./testdata/h2o/server.crt -I https://localhost:8444/status
HTTP/2 200
server: h2o/2.3.0-DEV@123f5e2b6
cache-control: no-cache
content-type: text/html; charset=utf-8
last-modified: Tue, 20 Feb 2024 01:02:58 GMT
etag: "65d3fa42-17a1"
accept-ranges: bytes
content-length: 6049
```

The h2o service is running an http CONNECT proxy so you can use curl with it directly as a test.

Using https:
```
$ curl --proxy-cacert ./testdata/h2o/server.crt --proxy https://localhost:8444 -I  https://ipinfo.io
HTTP/1.1 200 OK
Connection: close
Server: h2o/2.3.0-DEV@123f5e2b6

HTTP/2 200
server: nginx/1.24.0
date: Thu, 07 Mar 2024 19:28:24 GMT
content-type: application/json; charset=utf-8
content-length: 322
```

Using http:
```
$ curl --proxy http://localhost:8081 -I  https://ipinfo.io
HTTP/1.1 200 OK
Connection: close
Server: h2o/2.3.0-DEV@123f5e2b6

HTTP/2 200
server: nginx/1.24.0
date: Thu, 07 Mar 2024 19:29:29 GMT
content-type: application/json; charset=utf-8
content-length: 322
```

If for example we wanted to try out the relay http proxy we could start it up targeting the h2o container:
```
$ go run ./example/relay-http-proxy -invisvRelay localhost -invisvRelayPort 8444  -token fake-token -verbose=true -certDataFile ./testdata/h2o/server.crt
```

In a new terminal, make a request using the proxy:
```
$ curl --proxy http://localhost:32190 -I  https://duckduckgo.com
HTTP/1.1 200 OK
Content-Length: 0

HTTP/2 200
server: nginx
date: Tue, 27 Feb 2024 21:25:13 GMT
content-type: text/html; charset=UTF-8
content-length: 115553
vary: Accept-Encoding
```
🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉

Programatically, we'd use the address `localhost:8444` as our `ClientConfig.ProxyAddr`.

Don't forget to stop the docker container afterwards:
```
$ docker-compose down
```

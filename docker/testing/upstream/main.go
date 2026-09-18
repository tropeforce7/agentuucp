// upstream is the container suite's stand-in for api.anthropic.com, and
// the handler's client for it, in one static binary the image carries
// beside the forge. It exists so that the rows about the key-holding proxy
// can prove what reached the upstream and what the handler was given
// without Claude Code, which the containers do not have, and without curl,
// which the image does not carry.
//
//	upstream serve LOG     listen on 127.0.0.1 at a port of the kernel's
//	                       choosing, print the address, and record one line
//	                       per request to LOG: the method, the path, the
//	                       first six characters and the length of x-api-key,
//	                       and whether an authorization header came — never
//	                       the whole key, since a log is a file anybody on
//	                       the machine might read one day
//	upstream ask           POST $ANTHROPIC_BASE_URL/v1/messages with
//	                       $ANTHROPIC_API_KEY in x-api-key, as Claude Code
//	                       does, and print the status and the body
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		if len(os.Args) != 3 {
			usage()
		}
		serve(os.Args[2])
	case "ask":
		ask()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: upstream serve LOG | upstream ask")
	os.Exit(2)
}

func serve(logPath string) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	log, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(l.Addr().String())
	os.Stdout.Sync()
	http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		key := r.Header.Get("x-api-key")
		shown := key
		if len(shown) > 6 {
			shown = shown[:6] + "…"
		}
		auth := "absent"
		if r.Header.Get("authorization") != "" {
			auth = "present"
		}
		fmt.Fprintf(log, "%s %s key=%s len=%d authorization=%s\n", r.Method, r.URL.Path, shown, len(key), auth)
		log.Sync()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"seen":true}`)
	}))
}

func ask() {
	base := os.Getenv("ANTHROPIC_BASE_URL")
	if base == "" {
		fmt.Println("no ANTHROPIC_BASE_URL")
		os.Exit(1)
	}
	req, err := http.NewRequest("POST", base+"/v1/messages", strings.NewReader(`{"hello":"there"}`))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	req.Header.Set("x-api-key", os.Getenv("ANTHROPIC_API_KEY"))
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("status %d %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
}

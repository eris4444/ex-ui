package controller

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
)

// newPacketPanel serves the proxy route from a real HTTP server rather than a
// ResponseRecorder: gin's ResponseWriter forwards CloseNotify to the writer
// underneath it, and httputil.ReverseProxy calls it, so a recorder panics where
// production never would. Building the controller directly also keeps the test
// off the process environment and the real packet-tunnel port.
func newPacketPanel(t *testing.T, upstream, secret string) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)

	target, err := url.Parse(upstream)
	if err != nil {
		t.Fatalf("parse upstream %q: %v", upstream, err)
	}
	a := &PacketController{target: target, secret: secret}

	engine := gin.New()
	engine.Any("/panel/packet/*path", a.proxy)

	panel := httptest.NewServer(engine)
	t.Cleanup(panel.Close)
	return panel
}

func TestPacketProxyForwardsToUpstream(t *testing.T) {
	type captured struct {
		path   string
		query  string
		secret string
		cookie string
		host   string
	}
	var got captured

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = captured{
			path:   r.URL.Path,
			query:  r.URL.RawQuery,
			secret: r.Header.Get("X-Packet-Secret"),
			cookie: r.Header.Get("Cookie"),
			host:   r.Host,
		}
		_, _ = w.Write([]byte("packet-tunnel ok"))
	}))
	t.Cleanup(upstream.Close)

	panel := newPacketPanel(t, upstream.URL, "s3cr3t")

	req, err := http.NewRequest(http.MethodGet, panel.URL+"/panel/packet/services?filter=active", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Cookie", "3x-ui=session-value")

	resp, err := panel.Client().Do(req)
	if err != nil {
		t.Fatalf("request panel: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.StatusCode, body)
	}
	if string(body) != "packet-tunnel ok" {
		t.Errorf("body = %q, want the upstream response passed through", body)
	}

	// The /panel/packet prefix belongs to the panel: packet-tunnel serves
	// /services, and would 404 if the prefix were forwarded verbatim.
	if got.path != "/services" {
		t.Errorf("upstream path = %q, want %q", got.path, "/services")
	}
	if got.query != "filter=active" {
		t.Errorf("upstream query = %q, want %q", got.query, "filter=active")
	}
	if got.secret != "s3cr3t" {
		t.Errorf("X-Packet-Secret = %q, want %q", got.secret, "s3cr3t")
	}
	// The panel session cookie is meaningless to packet-tunnel's Flask session
	// and must never be forwarded.
	if got.cookie != "" {
		t.Errorf("Cookie = %q, want it stripped", got.cookie)
	}
	if want := upstream.Listener.Addr().String(); got.host != want {
		t.Errorf("Host = %q, want upstream host %q", got.host, want)
	}
}

func TestPacketProxyOmitsSecretHeaderWhenUnset(t *testing.T) {
	var present bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["X-Packet-Secret"]
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	panel := newPacketPanel(t, upstream.URL, "")

	resp, err := panel.Client().Get(panel.URL + "/panel/packet/")
	if err != nil {
		t.Fatalf("request panel: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	// With no secret configured the header must be absent entirely, so
	// packet-tunnel falls back to its own login instead of comparing an empty
	// header against an empty configured secret and letting everything through.
	if present {
		t.Error("X-Packet-Secret was sent even though no secret is configured")
	}
}

func TestPacketProxyReportsUnreachableUpstream(t *testing.T) {
	// Port 9 (discard) has nothing listening on loopback in CI, so the dial
	// fails fast instead of hanging.
	panel := newPacketPanel(t, "http://127.0.0.1:9", "s3cr3t")

	resp, err := panel.Client().Get(panel.URL + "/panel/packet/")
	if err != nil {
		t.Fatalf("request panel: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// A packet-tunnel that is not running must read as a gateway failure rather
	// than a panic or a blank 200.
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when packet-tunnel is down", resp.StatusCode)
	}
}

package controller

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/3x-ui/v3/internal/web/middleware"
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
	// The real engine installs this globally, and its X-Frame-Options: DENY plus
	// nonce-only script-src are exactly what the proxy has to override for the
	// tab to render, so the test is only meaningful with it in place.
	engine.Use(middleware.SecurityHeadersMiddleware(false))
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

func TestPacketProxyAllowsSameOriginFraming(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Some Flask deployments send their own framing headers; they must not
		// survive alongside the panel's, since browsers honour the stricter one.
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		_, _ = w.Write([]byte("<html>packet</html>"))
	}))
	t.Cleanup(upstream.Close)

	panel := newPacketPanel(t, upstream.URL, "s3cr3t")

	resp, err := panel.Client().Get(panel.URL + "/panel/packet/")
	if err != nil {
		t.Fatalf("request panel: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// DENY blocks the panel's own iframe too, which is what broke the tab.
	if got := resp.Header.Values("X-Frame-Options"); len(got) != 1 || got[0] != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options = %v, want exactly [SAMEORIGIN]", got)
	}

	csp := resp.Header.Values("Content-Security-Policy")
	if len(csp) != 1 {
		t.Fatalf("Content-Security-Policy = %v, want exactly one policy", csp)
	}
	if strings.Contains(csp[0], "frame-ancestors 'none'") {
		t.Errorf("CSP still forbids framing: %q", csp[0])
	}
	if !strings.Contains(csp[0], "frame-ancestors 'self'") {
		t.Errorf("CSP = %q, want frame-ancestors 'self'", csp[0])
	}
	// packet-tunnel's pages are built from inline scripts and handlers.
	if !strings.Contains(csp[0], "'unsafe-inline'") {
		t.Errorf("CSP = %q, want inline scripts allowed for the embedded panel", csp[0])
	}
}

func TestPacketProxyForwardsMountPoint(t *testing.T) {
	var scriptName string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scriptName = r.Header.Get("X-Script-Name")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	panel := newPacketPanel(t, upstream.URL, "s3cr3t")

	resp, err := panel.Client().Get(panel.URL + "/panel/packet/services")
	if err != nil {
		t.Fatalf("request panel: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Without this packet-tunnel's url_for() emits /services, which resolves
	// against the panel root inside the tab and 404s.
	if scriptName != "/panel/packet" {
		t.Errorf("X-Script-Name = %q, want %q", scriptName, "/panel/packet")
	}
}

package controller

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
)

// newPacketProxy builds a controller pointed at a stub standing in for
// packet-tunnel, bypassing NewPacketController so the test does not depend on
// process environment or on the real upstream port being free.
func newPacketProxy(t *testing.T, upstream string, secret string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	target, err := url.Parse(upstream)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}
	a := &PacketController{target: target, secret: secret}

	engine := gin.New()
	engine.Any("/panel/packet/*path", a.proxy)
	return engine
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
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("packet-tunnel ok"))
	}))
	t.Cleanup(upstream.Close)

	engine := newPacketProxy(t, upstream.URL, "s3cr3t")

	req := httptest.NewRequest(http.MethodGet, "/panel/packet/services?filter=active", nil)
	req.Header.Set("Cookie", "3x-ui=session-value")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != "packet-tunnel ok" {
		t.Errorf("body = %q, want upstream response passed through", body)
	}

	// The /panel/packet prefix must be stripped: packet-tunnel serves /services,
	// not /panel/packet/services.
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
	if got.host != upstream.Listener.Addr().String() {
		t.Errorf("Host = %q, want upstream host %q", got.host, upstream.Listener.Addr().String())
	}
}

func TestPacketProxyOmitsSecretHeaderWhenUnset(t *testing.T) {
	var present bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["X-Packet-Secret"]
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	engine := newPacketProxy(t, upstream.URL, "")

	req := httptest.NewRequest(http.MethodGet, "/panel/packet/", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// An empty secret must send no header at all, so packet-tunnel falls back to
	// its own login rather than comparing against an empty configured secret.
	if present {
		t.Error("X-Packet-Secret was sent even though no secret is configured")
	}
}

func TestPacketProxyReportsUnreachableUpstream(t *testing.T) {
	// Port 1 on loopback: reserved and never listening, so the dial fails fast.
	engine := newPacketProxy(t, "http://127.0.0.1:1", "s3cr3t")

	req := httptest.NewRequest(http.MethodGet, "/panel/packet/", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when packet-tunnel is down", w.Code)
	}
}

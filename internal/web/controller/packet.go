package controller

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// packetFrameCSP governs the proxied packet-tunnel subtree only. Its pages use
// inline <script>, inline event handlers and two CDNs, none of which survive the
// panel's nonce-based policy; frame-ancestors 'self' is what lets the Packet tab
// embed it. Served directly on its own port packet-tunnel sends no CSP at all,
// so this is stricter than reaching it that way, not looser.
const packetFrameCSP = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline'; " +
	"style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
	"font-src 'self' data: https://cdnjs.cloudflare.com https://fonts.gstatic.com; " +
	"img-src 'self' data: blob:; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"frame-ancestors 'self'; " +
	"base-uri 'self'; " +
	"form-action 'self'"

// packetProxySecretEnv names the environment variable holding the shared
// secret that authorizes proxied requests to packet-tunnel. It is generated
// per-installation, read only server-side, and never sent to the browser.
const packetProxySecretEnv = "PACKET_PROXY_SECRET"

// packetPortEnv overrides packet-tunnel's port for installs that changed it
// from the default in packet-tunnel's own settings page (PANEL_PORT/panel_port
// in eris4444/packet-tunnel's app.py).
const packetPortEnv = "PACKET_TUNNEL_PORT"

// defaultPacketPort matches packet-tunnel's own default (PANEL_PORT in app.py).
const defaultPacketPort = "7777"

// PacketController reverse-proxies /panel/packet/* to a packet-tunnel
// instance running on 127.0.0.1 on the same host, so it appears as a tab
// inside the panel without a second login. The route is gated by the panel's
// own session auth (same as every other /panel page); packet-tunnel is told
// to trust the request via a shared secret that only this server-side proxy
// knows.
type PacketController struct {
	BaseController
	target *url.URL
	secret string
}

// NewPacketController creates and registers the packet-tunnel proxy controller.
func NewPacketController(g *gin.RouterGroup) *PacketController {
	port := os.Getenv(packetPortEnv)
	if port == "" {
		port = defaultPacketPort
	}
	target, _ := url.Parse("http://127.0.0.1:" + port)
	a := &PacketController{
		target: target,
		secret: os.Getenv(packetProxySecretEnv),
	}
	a.initRouter(g)
	return a
}

func (a *PacketController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/panel")
	g.Use(a.checkLogin)
	g.Any("/packet/*path", a.proxy)
}

// proxy forwards the request to packet-tunnel, stripping the /panel/packet
// prefix and the Ex-ui session cookie (meaningless to packet-tunnel's own
// Flask session) and attaching the shared secret instead.
func (a *PacketController) proxy(c *gin.Context) {
	subPath := c.Param("path")
	if subPath == "" {
		subPath = "/"
	}
	secret := a.secret
	// packet-tunnel builds links with url_for(), which emits root-relative
	// paths. Inside the tab those would point at the panel root and 404, so the
	// mount point travels with the request and packet-tunnel prefixes its URLs
	// with it (see the SCRIPT_NAME middleware in eris4444/packet-tunnel).
	scriptName := strings.TrimSuffix(c.GetString("base_path"), "/") + "/panel/packet"

	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(a.target)
			r.Out.URL.Path = subPath
			r.Out.Host = a.target.Host
			r.Out.Header.Del("Cookie")
			r.Out.Header.Set("X-Script-Name", scriptName)
			if secret != "" {
				r.Out.Header.Set("X-Packet-Secret", secret)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			// Headers set below are already on the response writer; anything
			// upstream sends would be appended next to them and the browser then
			// enforces whichever is stricter.
			resp.Header.Del("X-Frame-Options")
			resp.Header.Del("Content-Security-Policy")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("packet-tunnel is not reachable on " + a.target.Host))
		},
	}

	// The panel denies framing outright and admits scripts only with its nonce.
	// Both are correct for the panel and both make an embedded packet-tunnel
	// unusable, so this subtree carries its own policy. SAMEORIGIN still refuses
	// framing by any other site, and the panel's own pages keep the strict one.
	h := c.Writer.Header()
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Content-Security-Policy", packetFrameCSP)

	rp.ServeHTTP(c.Writer, c.Request)
}

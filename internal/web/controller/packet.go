package controller

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/gin-gonic/gin"
)

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

	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(a.target)
			r.Out.URL.Path = subPath
			r.Out.Host = a.target.Host
			r.Out.Header.Del("Cookie")
			if secret != "" {
				r.Out.Header.Set("X-Packet-Secret", secret)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("packet-tunnel is not reachable on " + a.target.Host))
		},
	}
	rp.ServeHTTP(c.Writer, c.Request)
}

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

// packetUpstream is packet-tunnel's fixed local address; it is only ever
// reached through this proxy, so it does not need to be configurable.
const packetUpstream = "http://127.0.0.1:5000"

// PacketController reverse-proxies /panel/packet/* to a packet-tunnel
// instance running on the same host, so it appears as a tab inside the panel
// without a second login. The route is gated by the panel's own session auth
// (same as every other /panel page); packet-tunnel is told to trust the
// request via a shared secret that only this server-side proxy knows.
type PacketController struct {
	BaseController
	target *url.URL
	secret string
}

// NewPacketController creates and registers the packet-tunnel proxy controller.
func NewPacketController(g *gin.RouterGroup) *PacketController {
	target, _ := url.Parse(packetUpstream)
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
		Director: func(req *http.Request) {
			req.URL.Scheme = a.target.Scheme
			req.URL.Host = a.target.Host
			req.URL.Path = subPath
			req.Host = a.target.Host
			req.Header.Del("Cookie")
			if secret != "" {
				req.Header.Set("X-Packet-Secret", secret)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("packet-tunnel is not reachable on 127.0.0.1:5000"))
		},
	}
	rp.ServeHTTP(c.Writer, c.Request)
}

package server

import (
	"context"
	"net/http"
	"time"

	"github.com/jbub/geoip-forward-auth/internal/config"
	"github.com/jbub/geoip-forward-auth/internal/geoip"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func New(cfg config.Config, reg prometheus.Gatherer, svc *geoip.Service) *Server {
	mux := http.NewServeMux()
	mux.Handle("GET /health", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	mux.Handle("GET /auth", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		allow := svc.Allow(req)
		if !allow {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))

	return &Server{
		srv: &http.Server{
			Addr:         cfg.ListenAddr,
			Handler:      mux,
			ReadTimeout:  time.Second * 5,
			WriteTimeout: time.Second * 5,
			IdleTimeout:  time.Second * 5,
		},
	}
}

type Server struct {
	srv *http.Server
}

func (s *Server) ListenAndServe() error {
	return s.srv.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

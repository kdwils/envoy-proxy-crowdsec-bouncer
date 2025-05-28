package server

import (
	"fmt"
	"log"
	"net/http"

	"github.com/kdwils/envoy-gateway-bouncer/bouncer"
	"github.com/kdwils/envoy-gateway-bouncer/config"
)

type Server struct {
	bouncer bouncer.Bouncer
	config  config.Config
}

func NewServer(config config.Config, bouncer bouncer.Bouncer) *Server {
	s := &Server{
		config:  config,
		bouncer: bouncer,
	}

	return s
}

func (s Server) Serve(port int) error {
	http.HandleFunc("/healthz", s.Healthz())
	http.HandleFunc("/check", s.Check())
	addr := fmt.Sprintf(":%d", port)
	return http.ListenAndServe(addr, nil)
}

func (s Server) Healthz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

func (s Server) Check() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if s.bouncer == nil {
			http.Error(w, "bouncer not initialized", http.StatusForbidden)
			return
		}

		bounce, err := s.bouncer.Bounce(r)
		if err != nil {
			log.Printf("error checking request: %v", err)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if bounce {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

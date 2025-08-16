package ipaddr

import (
	"net"
	"net/http"
	"strings"
)

func NewRemoteAddrStrategy() *RemoteAddrStrategy {
	return &RemoteAddrStrategy{}
}

type RemoteAddrStrategy struct {
}

func (s *RemoteAddrStrategy) GetClientIP(req *http.Request) string {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		ip = req.RemoteAddr
	}
	return ip
}

func NewDepthStrategy(depth int) *DepthStrategy {
	return &DepthStrategy{depth: depth}
}

type DepthStrategy struct {
	depth int
}

func (s *DepthStrategy) GetClientIP(req *http.Request) string {
	header := req.Header.Get("X-Forwarded-For")
	if header == "" {
		return ""
	}

	ips := strings.Split(header, ",")
	if len(ips) < s.depth {
		return ""
	}

	ip := strings.TrimSpace(ips[len(ips)-s.depth])
	return ip
}

func NewPoolStrategy(pool []string) *PoolStrategy {
	ipPool := make(map[string]struct{}, len(pool))
	for _, ip := range pool {
		ipPool[ip] = struct{}{}
	}
	return &PoolStrategy{ipPool: ipPool}
}

type PoolStrategy struct {
	ipPool map[string]struct{}
}

func (s *PoolStrategy) GetClientIP(req *http.Request) string {
	header := req.Header.Get("X-Forwarded-For")
	if header == "" {
		return ""
	}

	ips := strings.Split(header, ",")
	for i := len(ips) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(ips[i])
		if len(ip) == 0 {
			continue
		}
		if _, exists := s.ipPool[ip]; !exists {
			return ip
		}
	}
	return ""
}

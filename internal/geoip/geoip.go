package geoip

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/jbub/geoip-forward-auth/internal/config"
	"github.com/jbub/geoip-forward-auth/internal/geoip/geoiperr"
	"github.com/jbub/geoip-forward-auth/internal/geoip/ip2location"
	"github.com/jbub/geoip-forward-auth/internal/geoip/maxmind"
	"github.com/jbub/geoip-forward-auth/internal/ipaddr"
	"github.com/prometheus/client_golang/prometheus"
)

type CountryResolver interface {
	ResolveCountryCode(addr netip.Addr) (string, error)
}

type ClientIPStrategy interface {
	GetClientIP(req *http.Request) string
}

func NewService(log *slog.Logger, cfg config.Config) (*Service, error) {
	var ipWhitelist []netip.Prefix
	for _, cidr := range cfg.CIDRWhitelist {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, err
		}
		ipWhitelist = append(ipWhitelist, prefix)
	}

	countryWhitelist := make(map[string]struct{}, len(cfg.CountryWhitelist))
	for _, cnt := range cfg.CountryWhitelist {
		countryWhitelist[cnt] = struct{}{}
	}

	countryBlacklist := make(map[string]struct{}, len(cfg.CountryBlacklist))
	for _, cnt := range cfg.CountryBlacklist {
		countryBlacklist[cnt] = struct{}{}
	}

	resolver, err := newResolver(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create resolver: %w", err)
	}

	clientIPStrat, err := newClientIPStrategy(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create client IP strategy: %w", err)
	}

	return &Service{
		log:              log,
		allowPrivate:     cfg.AllowPrivate,
		ipWhitelist:      ipWhitelist,
		resolver:         resolver,
		allowCache:       expirable.NewLRU[netip.Addr, allowEntry](cfg.CacheSize, nil, cfg.CacheTTL),
		countryWhitelist: countryWhitelist,
		countryBlacklist: countryBlacklist,
		clientIPStrat:    clientIPStrat,
		metrics:          newMetrics(),
	}, nil
}

func newResolver(cfg config.Config) (CountryResolver, error) {
	switch cfg.CountryResolver {
	case "ip2location":
		return ip2location.NewResolver(cfg.IP2LocationDatabase)
	case "maxmind":
		return maxmind.NewResolver(cfg.MaxmindDatabase)
	default:
		return nil, fmt.Errorf("unknown country resolver: %s", cfg.CountryResolver)
	}
}

func newClientIPStrategy(cfg config.Config) (ClientIPStrategy, error) {
	switch cfg.ClientIPStrategy {
	case "remote_addr":
		return ipaddr.NewRemoteAddrStrategy(), nil
	case "depth":
		return ipaddr.NewDepthStrategy(cfg.ClientIPStrategyDepth), nil
	case "pool":
		return ipaddr.NewPoolStrategy(cfg.ClientIPStrategyPool), nil
	default:
		return nil, fmt.Errorf("unknown client IP strategy: %s", cfg.ClientIPStrategy)
	}
}

type Service struct {
	log              *slog.Logger
	allowPrivate     bool
	ipWhitelist      []netip.Prefix
	countryWhitelist map[string]struct{}
	countryBlacklist map[string]struct{}
	resolver         CountryResolver
	clientIPStrat    ClientIPStrategy
	allowCache       *expirable.LRU[netip.Addr, allowEntry]
	metrics          *metrics
}

type allowEntry struct {
	allowed     bool
	countryCode string
	decision    string
}

func (s *Service) Allow(req *http.Request) bool {
	host := s.getHostname(req)
	if host == "" {
		s.log.LogAttrs(req.Context(), slog.LevelDebug, "no hostname found in request")
		return false
	}

	log := s.log.With(slog.String("host", host))
	addr, ok := s.getClientAddr(req)
	if !ok {
		log.LogAttrs(req.Context(), slog.LevelDebug, "no client address found in request")
		return false
	}

	log = log.With(slog.String("addr", addr.String()))
	if entry, cached := s.getCachedEntry(addr); cached {
		log.LogAttrs(req.Context(), slog.LevelDebug, "cache hit", slog.Bool("allowed", entry.allowed))
		return entry.allowed
	}

	entry := s.allow(req.Context(), log, addr)
	s.allowCache.Add(addr, entry)
	return entry.allowed
}

func (s *Service) Describe(descs chan<- *prometheus.Desc) {
	s.metrics.Describe(descs)
}

func (s *Service) Collect(metrics chan<- prometheus.Metric) {
	s.metrics.Collect(metrics)
}

func (s *Service) getCachedEntry(addr netip.Addr) (allowEntry, bool) {
	if entry, cached := s.allowCache.Get(addr); cached {
		s.metrics.recordCacheHit()
		return entry, true
	}
	s.metrics.recordCacheMiss()
	return allowEntry{}, false
}

func (s *Service) allow(ctx context.Context, log *slog.Logger, addr netip.Addr) allowEntry {
	if s.addrWhitelisted(ctx, log, addr) {
		return allowEntry{allowed: true, decision: "whitelisted"}
	}
	if s.allowPrivateAddr(ctx, log, addr) {
		return allowEntry{allowed: true, decision: "private_whitelisted"}
	}

	entry := s.allowCountry(ctx, log, addr)
	if entry.countryCode != "" {
		s.recordCountryDecision(ctx, log, entry)
	}
	return entry
}

func (s *Service) recordCountryDecision(ctx context.Context, log *slog.Logger, entry allowEntry) {
	s.metrics.recordCountryDecision(entry.countryCode, entry.decision)
	log.LogAttrs(ctx, slog.LevelInfo, "country decision", slog.String("country", entry.countryCode), slog.String("decision", entry.decision))
}

func (s *Service) allowPrivateAddr(ctx context.Context, log *slog.Logger, addr netip.Addr) bool {
	if s.allowPrivate && addr.IsPrivate() {
		log.LogAttrs(ctx, slog.LevelDebug, "private address allowed")
		return true
	}
	return false
}

func (s *Service) addrWhitelisted(ctx context.Context, log *slog.Logger, addr netip.Addr) bool {
	for _, prefix := range s.ipWhitelist {
		if prefix.Contains(addr) {
			log.LogAttrs(ctx, slog.LevelDebug, "address whitelisted by prefix", slog.String("prefix", prefix.String()))
			return true
		}
	}
	return false
}

func (s *Service) allowCountry(ctx context.Context, log *slog.Logger, addr netip.Addr) allowEntry {
	countryCode, err := s.resolver.ResolveCountryCode(addr)
	if err != nil {
		if errors.Is(err, geoiperr.ErrCountryCodeNotFound) {
			log.LogAttrs(ctx, slog.LevelDebug, "country code not found")
			return allowEntry{allowed: false}
		}

		log.LogAttrs(ctx, slog.LevelError, "unable to resolve country code", slog.String("error", err.Error()))
		return allowEntry{allowed: false}
	}

	countryCode = strings.ToLower(countryCode)
	if s.countryWhitelisted(countryCode) {
		return allowEntry{allowed: true, countryCode: countryCode, decision: "whitelisted"}
	}
	if s.countryBlacklisted(countryCode) {
		return allowEntry{allowed: false, countryCode: countryCode, decision: "blacklisted"}
	}
	return allowEntry{allowed: false, countryCode: countryCode, decision: "disallowed"}
}

func (s *Service) countryWhitelisted(countryCode string) bool {
	_, exists := s.countryWhitelist[countryCode]
	return exists
}

func (s *Service) countryBlacklisted(countryCode string) bool {
	_, exists := s.countryBlacklist[countryCode]
	return exists
}

func (s *Service) getHostname(req *http.Request) string {
	return req.Header.Get("X-Forwarded-Host")
}

func (s *Service) getClientAddr(req *http.Request) (netip.Addr, bool) {
	ip := s.clientIPStrat.GetClientIP(req)
	if ip == "" {
		return netip.Addr{}, false
	}
	if addr, err := netip.ParseAddr(ip); err == nil {
		return addr, true
	}
	return netip.Addr{}, false
}

func newMetrics() *metrics {
	return &metrics{
		countryDecisionCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "geoip",
				Name:      "country_decisions_total",
				Help:      "Total number of country decisions made, labeled by country code and decision.",
			},
			[]string{"country_code", "decision"},
		),
		cacheHitCounter: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "geoip",
				Name:      "cache_hits_total",
				Help:      "Total number of cache hits.",
			},
		),
		cacheMissCounter: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "geoip",
				Name:      "cache_misses_total",
				Help:      "Total number of cache misses.",
			},
		),
	}
}

type metrics struct {
	countryDecisionCounter *prometheus.CounterVec
	cacheHitCounter        prometheus.Counter
	cacheMissCounter       prometheus.Counter
}

func (m *metrics) recordCountryDecision(countryCode, decision string) {
	m.countryDecisionCounter.With(prometheus.Labels{
		"country_code": countryCode,
		"decision":     decision,
	}).Inc()
}

func (m *metrics) recordCacheHit() {
	m.cacheHitCounter.Inc()
}

func (m *metrics) recordCacheMiss() {
	m.cacheMissCounter.Inc()
}

func (m *metrics) Describe(descs chan<- *prometheus.Desc) {
	m.countryDecisionCounter.Describe(descs)
	m.cacheHitCounter.Describe(descs)
	m.cacheMissCounter.Describe(descs)
}

func (m *metrics) Collect(metrics chan<- prometheus.Metric) {
	m.countryDecisionCounter.Collect(metrics)
	m.cacheHitCounter.Collect(metrics)
	m.cacheMissCounter.Collect(metrics)
}

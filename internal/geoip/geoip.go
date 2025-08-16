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
)

type CountryResolver interface {
	ResolveCountryCode(addr netip.Addr) (string, error)
}

type ClientIPStrategy interface {
	GetClientIP(req *http.Request) string
}

func NewService(log *slog.Logger, cfg config.Config) (*Service, error) {
	cache := expirable.NewLRU[netip.Addr, bool](cfg.CacheSize, nil, cfg.CacheTTL)

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
		allowCache:       cache,
		countryWhitelist: countryWhitelist,
		countryBlacklist: countryBlacklist,
		clientIPStrat:    clientIPStrat,
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
	allowCache       *expirable.LRU[netip.Addr, bool]
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

	if allowed, cached := s.allowCache.Get(addr); cached {
		log.LogAttrs(req.Context(), slog.LevelDebug, "cache hit", slog.Bool("allowed", allowed))
		return allowed
	}

	allowed := s.allow(req.Context(), log, addr)
	s.allowCache.Add(addr, allowed)
	return allowed
}

func (s *Service) allow(ctx context.Context, log *slog.Logger, addr netip.Addr) bool {
	if s.addrWhitelisted(ctx, log, addr) {
		return true
	}
	if s.allowPrivateAddr(ctx, log, addr) {
		return true
	}
	return s.allowCountry(ctx, log, addr)
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

func (s *Service) allowCountry(ctx context.Context, log *slog.Logger, addr netip.Addr) bool {
	countryCode, err := s.resolver.ResolveCountryCode(addr)
	if err != nil {
		if errors.Is(err, geoiperr.ErrCountryCodeNotFound) {
			log.LogAttrs(ctx, slog.LevelDebug, "country code not found")
			return false
		}

		log.LogAttrs(ctx, slog.LevelError, "unable to resolve country code", slog.String("error", err.Error()))
		return false
	}

	countryCode = strings.ToLower(countryCode)

	if s.countryWhitelisted(countryCode) {
		s.logCountryDecision(ctx, log, countryCode, "whitelisted")
		return true
	}
	if s.countryBlacklisted(countryCode) {
		s.logCountryDecision(ctx, log, countryCode, "blacklisted")
		return false
	}

	s.logCountryDecision(ctx, log, countryCode, "disallowed")
	return false
}

func (s *Service) logCountryDecision(ctx context.Context, log *slog.Logger, countryCode, decision string) {
	log.LogAttrs(ctx, slog.LevelInfo, "country decision", slog.String("country", countryCode), slog.String("decision", decision))
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

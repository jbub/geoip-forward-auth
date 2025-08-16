package config

import (
	"fmt"
	"time"

	"github.com/urfave/cli/v2"
)

type Config struct {
	ListenAddr            string
	LogLevel              string
	CountryResolver       string
	AllowPrivate          bool
	CIDRWhitelist         []string
	CountryWhitelist      []string
	CountryBlacklist      []string
	CacheSize             int
	CacheTTL              time.Duration
	IP2LocationDatabase   string
	MaxmindDatabase       string
	ClientIPStrategy      string
	ClientIPStrategyDepth int
	ClientIPStrategyPool  []string
}

func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen-addr must be specified")
	}
	if c.LogLevel == "" {
		return fmt.Errorf("log-level must be specified")
	}
	if c.CountryResolver == "" {
		return fmt.Errorf("country-resolver must be specified")
	}
	if c.CacheSize <= 0 {
		return fmt.Errorf("cache-size must be greater than 0")
	}
	if c.CacheTTL <= 0 {
		return fmt.Errorf("cache-ttl must be greater than 0")
	}
	if c.ClientIPStrategy == "" {
		return fmt.Errorf("client-ip-strategy must be specified")
	}
	if c.ClientIPStrategy == "depth" && c.ClientIPStrategyDepth <= 0 {
		return fmt.Errorf("client-ip-strategy-depth must be greater than 0")
	}
	if c.ClientIPStrategy == "pool" && len(c.ClientIPStrategyPool) < 1 {
		return fmt.Errorf("client-ip-strategy-pool must contain at least one IP")
	}
	return nil
}

func FromCLIContext(ctx *cli.Context) Config {
	return Config{
		ListenAddr:            ctx.String("listen-addr"),
		LogLevel:              ctx.String("log-level"),
		CountryResolver:       ctx.String("country-resolver"),
		AllowPrivate:          ctx.Bool("allow-private"),
		CIDRWhitelist:         ctx.StringSlice("cidr-whitelist"),
		CountryWhitelist:      ctx.StringSlice("country-whitelist"),
		CountryBlacklist:      ctx.StringSlice("country-blacklist"),
		CacheSize:             ctx.Int("cache-size"),
		CacheTTL:              ctx.Duration("cache-ttl"),
		IP2LocationDatabase:   ctx.String("ip2location-database"),
		MaxmindDatabase:       ctx.String("maxmind-database"),
		ClientIPStrategy:      ctx.String("client-ip-strategy"),
		ClientIPStrategyDepth: ctx.Int("client-ip-strategy-depth"),
		ClientIPStrategyPool:  ctx.StringSlice("client-ip-strategy-pool"),
	}
}

package config

import (
	"fmt"
	"time"

	"github.com/urfave/cli/v2"
)

type Config struct {
	ListenAddr          string
	CountryResolver     string
	AllowPrivate        bool
	CIDRWhitelist       []string
	CountryWhitelist    []string
	CountryBlacklist    []string
	CacheSize           int
	CacheTTL            time.Duration
	IP2LocationDatabase string
	MaxmindDatabase     string
}

func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen-addr must be specified")
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
	return nil
}

func FromCLIContext(ctx *cli.Context) Config {
	return Config{
		ListenAddr:          ctx.String("listen-addr"),
		CountryResolver:     ctx.String("country-resolver"),
		AllowPrivate:        ctx.Bool("allow-private"),
		CIDRWhitelist:       ctx.StringSlice("cidr-whitelist"),
		CountryWhitelist:    ctx.StringSlice("country-whitelist"),
		CountryBlacklist:    ctx.StringSlice("country-blacklist"),
		CacheSize:           ctx.Int("cache-size"),
		CacheTTL:            ctx.Duration("cache-ttl"),
		IP2LocationDatabase: ctx.String("ip2location-database"),
		MaxmindDatabase:     ctx.String("maxmind-database"),
	}
}

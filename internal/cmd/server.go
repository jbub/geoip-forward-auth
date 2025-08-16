package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jbub/geoip-forward-auth/internal/config"
	"github.com/jbub/geoip-forward-auth/internal/geoip"
	"github.com/jbub/geoip-forward-auth/internal/server"

	"github.com/oklog/run"
	"github.com/urfave/cli/v2"
)

var Server = &cli.Command{
	Name:   "server",
	Usage:  "Starts the http server.",
	Action: runServer,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "listen-addr",
			Usage:   "Address on which to listen for incoming requests.",
			EnvVars: []string{"LISTEN_ADDR"},
			Value:   ":8080",
		},
		&cli.StringFlag{
			Name:    "log-level",
			Usage:   "Logging level (debug, info, warn, error).",
			EnvVars: []string{"LOG_LEVEL"},
			Value:   "info",
		},
		&cli.StringFlag{
			Name:    "country-resolver",
			Usage:   "Country resolver to use (ip2location or maxmind).",
			EnvVars: []string{"COUNTRY_RESOLVER"},
			Value:   "ip2location",
		},
		&cli.BoolFlag{
			Name:    "allow-private",
			Usage:   "Allow requests from private IP addresses.",
			EnvVars: []string{"ALLOW_PRIVATE"},
			Value:   false,
		},
		&cli.StringSliceFlag{
			Name:    "cidr-whitelist",
			Usage:   "CIDR ranges to whitelist. Requests from these IPs will be allowed regardless of country.",
			EnvVars: []string{"CIDR_WHITELIST"},
		},
		&cli.StringSliceFlag{
			Name:    "country-whitelist",
			Usage:   "List of country codes to whitelist. Requests from these countries will be allowed.",
			EnvVars: []string{"COUNTRY_WHITELIST"},
		},
		&cli.StringSliceFlag{
			Name:    "country-blacklist",
			Usage:   "List of country codes to blacklist. Requests from these countries will be denied.",
			EnvVars: []string{"COUNTRY_BLACKLIST"},
		},
		&cli.IntFlag{
			Name:    "cache-size",
			Usage:   "Size of the in-memory cache for country lookups.",
			EnvVars: []string{"CACHE_SIZE"},
			Value:   1000,
		},
		&cli.DurationFlag{
			Name:    "cache-ttl",
			Usage:   "Time-to-live for cache entries.",
			EnvVars: []string{"CACHE_TTL"},
			Value:   time.Hour * 24,
		},
		&cli.StringFlag{
			Name:    "ip2location-database",
			Usage:   "Path to the IP2Location database file.",
			EnvVars: []string{"IP2LOCATION_DATABASE"},
		},
		&cli.StringFlag{
			Name:    "maxmind-database",
			Usage:   "Path to the MaxMind database file.",
			EnvVars: []string{"MAXMIND_DATABASE"},
		},
		&cli.StringFlag{
			Name:    "client-ip-strategy",
			Usage:   "Strategy to use for extracting client IP (remote-addr, depth, pool).",
			EnvVars: []string{"CLIENT_IP_STRATEGY"},
			Value:   "remote-addr",
		},
		&cli.IntFlag{
			Name:    "client-ip-strategy-depth",
			Usage:   "Depth for the depth strategy (number of hops to consider).",
			EnvVars: []string{"CLIENT_IP_STRATEGY_DEPTH"},
			Value:   1,
		},
		&cli.StringSliceFlag{
			Name:    "client-ip-strategy-pool",
			Usage:   "Pool of IPs to use for the pool strategy. First IP not in this pool will be used.",
			EnvVars: []string{"CLIENT_IP_STRATEGY_POOL"},
		},
	},
}

func runServer(cliCtx *cli.Context) error {
	cfg := config.FromCLIContext(cliCtx)
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	logLvl, err := parseLogLevel(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("unable to parse log level: %w", err)
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLvl,
	}))

	svc, err := geoip.NewService(log, cfg)
	if err != nil {
		return fmt.Errorf("unable to create geoip service: %w", err)
	}

	srv := server.New(cfg, svc)

	var grp run.Group
	grp.Add(func() error {
		return srv.ListenAndServe()
	}, func(err error) {
		_ = srv.Shutdown(context.Background())
	})

	log.LogAttrs(context.Background(), slog.LevelInfo, "server listening",
		slog.String("server_addr", cfg.ListenAddr),
		slog.String("country_resolver", cfg.CountryResolver),
		slog.String("client_ip_strategy", cfg.ClientIPStrategy),
	)
	return grp.Run()
}

func parseLogLevel(level string) (slog.Level, error) {
	switch level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level: %s", level)
	}
}

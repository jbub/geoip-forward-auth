package maxmind

import (
	"fmt"
	"net/netip"

	"github.com/jbub/geoip-forward-auth/internal/geoip/geoiperr"
	"github.com/oschwald/geoip2-golang/v2"
)

func NewResolver(databasePath string) (*Resolver, error) {
	db, err := geoip2.Open(databasePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open maxmind database: %w", err)
	}
	return &Resolver{db: db}, nil
}

type Resolver struct {
	db *geoip2.Reader
}

func (r *Resolver) ResolveCountryCode(addr netip.Addr) (string, error) {
	rec, err := r.db.Country(addr)
	if err != nil {
		return "", err
	}
	if !rec.HasData() {
		return "", fmt.Errorf("%w: %v", geoiperr.ErrCountryCodeNotFound, err)
	}
	return rec.Country.ISOCode, nil
}

package ip2location

import (
	"fmt"
	"net/netip"

	"github.com/ip2location/ip2location-go/v9"
	"github.com/jbub/geoip-forward-auth/internal/geoip/geoiperr"
)

func NewResolver(databasePath string) (*Resolver, error) {
	db, err := ip2location.OpenDB(databasePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open ip2location database: %w", err)
	}
	return &Resolver{db: db}, nil
}

type Resolver struct {
	db *ip2location.DB
}

func (r *Resolver) ResolveCountryCode(addr netip.Addr) (string, error) {
	rec, err := r.db.Get_country_short(addr.String())
	if err != nil {
		return "", err
	}
	if rec.Country_short == "-" {
		return "", fmt.Errorf("%w: %v", geoiperr.ErrCountryCodeNotFound, err)
	}
	return rec.Country_short, nil
}

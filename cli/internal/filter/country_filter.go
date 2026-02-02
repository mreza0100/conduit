/*
 * Copyright (c) 2026, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// Package filter provides IP filtering based on country
package filter

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// CountryFilter filters connections based on country
type CountryFilter struct {
	db               *geoip2.Reader
	allowedCountries map[string]bool
	mu               sync.RWMutex

	// Stats
	allowedCount int64
	blockedCount int64
	relayCount   int64
}

// NewCountryFilter creates a new country filter
func NewCountryFilter(dbPath string, allowedCountries []string) (*CountryFilter, error) {
	fmt.Println("")
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║           COUNTRY FILTER INITIALIZATION                        ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Printf("[FILTER-INIT] Starting country filter initialization...\n")
	fmt.Printf("[FILTER-INIT] GeoIP database path: %s\n", dbPath)
	fmt.Printf("[FILTER-INIT] Allowed countries received: %v\n", allowedCountries)
	fmt.Printf("[FILTER-INIT] Number of allowed countries: %d\n", len(allowedCountries))

	fmt.Printf("[FILTER-INIT] Opening GeoIP database...\n")
	db, err := geoip2.Open(dbPath)
	if err != nil {
		fmt.Printf("[FILTER-INIT] ERROR: Failed to open GeoIP database: %v\n", err)
		return nil, err
	}
	fmt.Printf("[FILTER-INIT] GeoIP database loaded successfully\n")

	allowed := make(map[string]bool)
	fmt.Printf("[FILTER-INIT] Building allowed countries map:\n")
	for i, cc := range allowedCountries {
		allowed[cc] = true
		fmt.Printf("[FILTER-INIT]   %d. Country code: %s -> ALLOWED\n", i+1, cc)
	}

	fmt.Println("")
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║           FILTER RULES SUMMARY                                 ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Allowed countries: %-42v ║\n", allowedCountries)
	fmt.Println("║  Private IPs (TURN relays): ALWAYS ALLOWED                     ║")
	fmt.Println("║  Unknown country IPs: BLOCKED                                  ║")
	fmt.Println("║  All other countries: BLOCKED                                  ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println("")
	fmt.Printf("[FILTER-INIT] Country filter initialized and ready!\n")
	fmt.Printf("[FILTER-INIT] Waiting for incoming connections...\n")
	fmt.Println("")

	return &CountryFilter{
		db:               db,
		allowedCountries: allowed,
	}, nil
}

// IsAllowed checks if an IP is allowed based on country
// Returns: allowed (bool), countryCode (string), isRelay (bool for private IPs)
func (f *CountryFilter) IsAllowed(ipStr string) (bool, string, bool) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("%s [FILTER-DEBUG] IsAllowed called with IP: %s\n", timestamp, ipStr)

	ip := net.ParseIP(ipStr)
	if ip == nil {
		// Invalid IP, block it
		f.mu.Lock()
		f.blockedCount++
		f.mu.Unlock()
		fmt.Printf("%s [FILTER-DEBUG] Invalid IP format: %s - BLOCKED\n", timestamp, ipStr)
		return false, "", false
	}

	// Allow private/loopback IPs (TURN relay connections)
	if isPrivateIP(ip) {
		f.mu.Lock()
		f.relayCount++
		total := f.relayCount
		f.mu.Unlock()
		fmt.Printf("%s [FILTER-DEBUG] Private/Relay IP: %s - ALLOWED (total relays: %d)\n", timestamp, ipStr, total)
		return true, "RELAY", true
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	record, err := f.db.Country(ip)
	if err != nil || record.Country.IsoCode == "" {
		// Can't determine country, block it
		f.blockedCount++
		fmt.Printf("%s [FILTER-DEBUG] GeoIP lookup failed for %s (err: %v) - BLOCKED (total blocked: %d)\n", timestamp, ipStr, err, f.blockedCount)
		return false, "UNKNOWN", false
	}

	countryCode := record.Country.IsoCode
	countryName := record.Country.Names["en"]
	if f.allowedCountries[countryCode] {
		f.allowedCount++
		fmt.Printf("%s [FILTER-DEBUG] IP %s is from %s (%s) - ALLOWED (total allowed: %d)\n", timestamp, ipStr, countryName, countryCode, f.allowedCount)
		return true, countryCode, false
	}

	f.blockedCount++
	fmt.Printf("%s [FILTER-DEBUG] IP %s is from %s (%s) - BLOCKED (total blocked: %d)\n", timestamp, ipStr, countryName, countryCode, f.blockedCount)
	return false, countryCode, false
}

// GetStats returns the current filter statistics
func (f *CountryFilter) GetStats() (allowed, blocked, relay int64) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.allowedCount, f.blockedCount, f.relayCount
}

// Close closes the GeoIP database
func (f *CountryFilter) Close() error {
	if f.db != nil {
		return f.db.Close()
	}
	return nil
}

// isPrivateIP checks if an IP is private/internal
func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

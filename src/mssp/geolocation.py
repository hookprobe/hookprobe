"""
GeoIP2 Integration for HookProbe Liberty

Provides accurate IP-based geolocation for device tracking.
Uses MaxMind GeoIP2 database for production-ready geolocation.

Features:
- Country, region, city identification
- Latitude/longitude coordinates
- ASN (Autonomous System Number) lookup
- ISP identification
- Fallback to IP-API.com for development

Setup:
1. Download MaxMind GeoLite2 databases:
   - GeoLite2-City.mmdb
   - GeoLite2-ASN.mmdb

2. Place in /var/lib/hookprobe/geoip/

3. Update database monthly (cron job)
"""

import os
import requests
from typing import Optional
from dataclasses import dataclass

try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    print("WARNING: geoip2 not installed. Install: pip install geoip2")


@dataclass
class GeoLocation:
    """Geographic location information."""
    ip_address: str
    country: str
    country_code: str
    region: str
    city: str
    latitude: float
    longitude: float
    asn: int
    asn_org: str  # ISP/Organization
    timezone: str
    accuracy_radius: int  # km


class GeoIPService:
    """
    GeoIP service using MaxMind GeoIP2.

    Provides accurate geolocation for IP addresses.
    """

    def __init__(
        self,
        city_db_path: str = "/var/lib/hookprobe/geoip/GeoLite2-City.mmdb",
        asn_db_path: str = "/var/lib/hookprobe/geoip/GeoLite2-ASN.mmdb"
    ):
        """
        Args:
            city_db_path: Path to GeoLite2-City database
            asn_db_path: Path to GeoLite2-ASN database
        """
        self.city_db_path = city_db_path
        self.asn_db_path = asn_db_path

        self.city_reader = None
        self.asn_reader = None

        if GEOIP2_AVAILABLE:
            self._init_databases()

    def _init_databases(self):
        """Initialize GeoIP2 database readers."""
        try:
            if os.path.exists(self.city_db_path):
                self.city_reader = geoip2.database.Reader(self.city_db_path)
            else:
                print(f"WARNING: GeoIP2 City database not found: {self.city_db_path}")

            if os.path.exists(self.asn_db_path):
                self.asn_reader = geoip2.database.Reader(self.asn_db_path)
            else:
                print(f"WARNING: GeoIP2 ASN database not found: {self.asn_db_path}")

        except Exception as e:
            print(f"GeoIP2 initialization error: {e}")

    def geolocate(self, ip_address: str) -> Optional[GeoLocation]:
        """
        Geolocate IP address.

        Args:
            ip_address: IP address to geolocate

        Returns:
            GeoLocation or None if lookup fails
        """
        # Skip private/local IPs
        if self._is_private_ip(ip_address):
            return None

        # Try MaxMind GeoIP2 first (most accurate)
        if GEOIP2_AVAILABLE and self.city_reader:
            location = self._geolocate_maxmind(ip_address)
            if location:
                return location

        # Fallback to IP-API.com (free, but rate limited)
        return self._geolocate_ipapi(ip_address)

    def _geolocate_maxmind(self, ip_address: str) -> Optional[GeoLocation]:
        """Geolocate using MaxMind GeoIP2 databases."""
        try:
            # City lookup
            city_response = self.city_reader.city(ip_address)

            # ASN lookup
            asn_number = 0
            asn_org = "Unknown"
            if self.asn_reader:
                try:
                    asn_response = self.asn_reader.asn(ip_address)
                    asn_number = asn_response.autonomous_system_number or 0
                    asn_org = asn_response.autonomous_system_organization or "Unknown"
                except geoip2.errors.AddressNotFoundError:
                    pass

            return GeoLocation(
                ip_address=ip_address,
                country=city_response.country.name or "Unknown",
                country_code=city_response.country.iso_code or "XX",
                region=city_response.subdivisions.most_specific.name if city_response.subdivisions else "Unknown",
                city=city_response.city.name or "Unknown",
                latitude=city_response.location.latitude or 0.0,
                longitude=city_response.location.longitude or 0.0,
                asn=asn_number,
                asn_org=asn_org,
                timezone=city_response.location.time_zone or "UTC",
                accuracy_radius=city_response.location.accuracy_radius or 0
            )

        except geoip2.errors.AddressNotFoundError:
            print(f"IP not found in GeoIP2 database: {ip_address}")
            return None
        except Exception as e:
            print(f"MaxMind lookup error: {e}")
            return None

    def _geolocate_ipapi(self, ip_address: str) -> Optional[GeoLocation]:
        """
        Geolocate using IP-API.com (fallback).

        Free tier: 45 requests/minute
        """
        try:
            url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,as"

            response = requests.get(url, timeout=5)
            data = response.json()

            if data.get('status') != 'success':
                return None

            # Parse ASN from "as" field (format: "AS7922 Comcast Cable")
            asn_str = data.get('as', 'AS0 Unknown')
            asn_parts = asn_str.split(' ', 1)
            asn_number = int(asn_parts[0].replace('AS', '')) if asn_parts[0].startswith('AS') else 0
            asn_org = asn_parts[1] if len(asn_parts) > 1 else data.get('isp', 'Unknown')

            return GeoLocation(
                ip_address=ip_address,
                country=data.get('country', 'Unknown'),
                country_code=data.get('countryCode', 'XX'),
                region=data.get('regionName', 'Unknown'),
                city=data.get('city', 'Unknown'),
                latitude=float(data.get('lat', 0.0)),
                longitude=float(data.get('lon', 0.0)),
                asn=asn_number,
                asn_org=asn_org,
                timezone=data.get('timezone', 'UTC'),
                accuracy_radius=50  # Estimate for IP-API
            )

        except Exception as e:
            print(f"IP-API lookup error: {e}")
            return None

    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP is private/local."""
        private_ranges = [
            '10.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
            '192.168.',
            '127.',
            '169.254.',
            '100.64.', '100.65.', '100.66.', '100.67.',  # CGNAT
            '100.68.', '100.69.', '100.70.', '100.71.',
            '100.72.', '100.73.', '100.74.', '100.75.',
            '100.76.', '100.77.', '100.78.', '100.79.',
            '100.80.', '100.81.', '100.82.', '100.83.',
            '100.84.', '100.85.', '100.86.', '100.87.',
            '100.88.', '100.89.', '100.90.', '100.91.',
            '100.92.', '100.93.', '100.94.', '100.95.',
            '100.96.', '100.97.', '100.98.', '100.99.',
            '100.100.', '100.101.', '100.102.', '100.103.',
            '100.104.', '100.105.', '100.106.', '100.107.',
            '100.108.', '100.109.', '100.110.', '100.111.',
            '100.112.', '100.113.', '100.114.', '100.115.',
            '100.116.', '100.117.', '100.118.', '100.119.',
            '100.120.', '100.121.', '100.122.', '100.123.',
            '100.124.', '100.125.', '100.126.', '100.127.',
        ]

        for prefix in private_ranges:
            if ip_address.startswith(prefix):
                return True

        return False

    def close(self):
        """Close database readers."""
        if self.city_reader:
            self.city_reader.close()
        if self.asn_reader:
            self.asn_reader.close()


# Example usage
if __name__ == '__main__':
    print("=== GeoIP2 Service Test ===\n")

    service = GeoIPService()

    # Test IPs
    test_ips = [
        "8.8.8.8",  # Google DNS (US)
        "1.1.1.1",  # Cloudflare (Various)
        "104.16.132.229",  # Example
    ]

    for ip in test_ips:
        print(f"Testing IP: {ip}")
        location = service.geolocate(ip)

        if location:
            print(f"  Country: {location.country} ({location.country_code})")
            print(f"  Region: {location.region}")
            print(f"  City: {location.city}")
            print("  Coordinates: [REDACTED]")
            print(f"  ASN: AS{location.asn} ({location.asn_org})")
            print(f"  Timezone: {location.timezone}")
            print(f"  Accuracy: ±{location.accuracy_radius}km")
        else:
            print("  Lookup failed")

        print()

    service.close()
    print("✓ GeoIP2 test complete")

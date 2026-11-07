#!/usr/bin/env python3
"""
IP Geolocation Resolver for HookProbe Globe Visualization

Resolves IP addresses to geographic coordinates for globe placement.
Uses GeoIP2 database (MaxMind GeoLite2 - free version available).
"""

import logging
from typing import Optional, Dict, Any, Tuple
from functools import lru_cache

logger = logging.getLogger(__name__)

# Try to import geoip2, but don't fail if not available
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    logger.warning("geoip2 not installed. IP geolocation will use fallback.")


class GeoResolver:
    """
    Resolves IP addresses to lat/lng coordinates.

    Usage:
        resolver = GeoResolver("/path/to/GeoLite2-City.mmdb")
        lat, lng, info = resolver.resolve("8.8.8.8")
    """

    # Fallback locations for common IP ranges (for demo/testing)
    FALLBACK_LOCATIONS: Dict[str, Tuple[float, float, str]] = {
        "8.8.8.8": (37.751, -97.822, "Google DNS (US)"),
        "1.1.1.1": (-33.494, 143.210, "Cloudflare DNS (AU)"),
        "208.67.222.222": (37.7749, -122.4194, "OpenDNS (SF)"),
        # Private ranges - return None
        "10.": (0, 0, "Private"),
        "172.16.": (0, 0, "Private"),
        "192.168.": (0, 0, "Private"),
    }

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the geo resolver.

        Args:
            db_path: Path to GeoLite2-City.mmdb database file.
                     Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
        """
        self.reader = None
        self.db_path = db_path

        if db_path and GEOIP_AVAILABLE:
            try:
                self.reader = geoip2.database.Reader(db_path)
                logger.info(f"GeoIP database loaded: {db_path}")
            except FileNotFoundError:
                logger.warning(f"GeoIP database not found: {db_path}")
            except Exception as e:
                logger.warning(f"Failed to load GeoIP database: {e}")

    @lru_cache(maxsize=10000)
    def resolve(self, ip: str) -> Tuple[Optional[float], Optional[float], Dict[str, Any]]:
        """
        Resolve an IP address to geographic coordinates.

        Args:
            ip: IP address string

        Returns:
            Tuple of (latitude, longitude, info_dict)
            Returns (None, None, {}) if resolution fails
        """
        # Check for private IP ranges
        for prefix, (lat, lng, label) in self.FALLBACK_LOCATIONS.items():
            if ip.startswith(prefix):
                if label == "Private":
                    return None, None, {"error": "Private IP"}
                return lat, lng, {"label": label, "source": "fallback"}

        # Try GeoIP database
        if self.reader:
            try:
                response = self.reader.city(ip)
                return (
                    response.location.latitude,
                    response.location.longitude,
                    {
                        "city": response.city.name,
                        "country": response.country.name,
                        "country_code": response.country.iso_code,
                        "source": "geoip"
                    }
                )
            except geoip2.errors.AddressNotFoundError:
                logger.debug(f"IP not found in database: {ip}")
            except Exception as e:
                logger.warning(f"GeoIP lookup failed for {ip}: {e}")

        # Final fallback - return approximate center based on first octet
        # This is very rough but better than nothing for demos
        return self._rough_estimate(ip)

    def _rough_estimate(self, ip: str) -> Tuple[Optional[float], Optional[float], Dict[str, Any]]:
        """
        Very rough geographic estimate based on IP first octet.
        Only used as last resort for demos.
        """
        try:
            first_octet = int(ip.split(".")[0])

            # Very rough regional estimates (for demo purposes only)
            if first_octet < 50:
                return 40.0, -100.0, {"label": "Americas (estimated)", "source": "estimate"}
            elif first_octet < 100:
                return 50.0, 10.0, {"label": "Europe (estimated)", "source": "estimate"}
            elif first_octet < 150:
                return 35.0, 105.0, {"label": "Asia (estimated)", "source": "estimate"}
            else:
                return 0.0, 0.0, {"label": "Unknown", "source": "estimate"}
        except (ValueError, IndexError):
            return None, None, {"error": "Invalid IP"}

    def close(self) -> None:
        """Close the GeoIP database reader."""
        if self.reader:
            self.reader.close()


# Global instance for convenience
_resolver: Optional[GeoResolver] = None


def get_resolver(db_path: Optional[str] = None) -> GeoResolver:
    """Get or create the global GeoResolver instance."""
    global _resolver
    if _resolver is None:
        _resolver = GeoResolver(db_path)
    return _resolver


if __name__ == "__main__":
    # Test the resolver
    resolver = GeoResolver()

    test_ips = ["8.8.8.8", "1.1.1.1", "192.168.1.1", "123.45.67.89"]
    for ip in test_ips:
        lat, lng, info = resolver.resolve(ip)
        # Redact/mask sensitive latitude/longitude data from output
        display = {}
        if "error" in info:
            display["status"] = info["error"]
        else:
            display["label"] = info.get("label", "")
            display["country"] = info.get("country", "")
            display["country_code"] = info.get("country_code", "")
            display["source"] = info.get("source", "")
        print(f"{ip}: location=REDACTED, info={display}")

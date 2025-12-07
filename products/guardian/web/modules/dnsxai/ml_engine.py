"""
dnsXai ML Engine - AI-Powered DNS Protection
Implements domain classification, CNAME uncloaking, federated learning,
real-time threat detection, and confidence scoring.
"""
import os
import re
import math
import json
import time
import hashlib
import logging
import threading
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional, Any

# ML imports - with fallbacks for lightweight deployment
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

logger = logging.getLogger(__name__)

# Paths
ML_DATA_DIR = '/opt/hookprobe/guardian/dns-shield/ml'
MODEL_PATH = f'{ML_DATA_DIR}/domain_classifier.joblib'
SCALER_PATH = f'{ML_DATA_DIR}/feature_scaler.joblib'
TRAINING_DATA_PATH = f'{ML_DATA_DIR}/training_data.json'
CNAME_CACHE_PATH = f'{ML_DATA_DIR}/cname_cache.json'
FEDERATED_PATH = f'{ML_DATA_DIR}/federated_updates.json'
THREAT_LOG_PATH = f'{ML_DATA_DIR}/threat_detections.json'

# Known ad/tracking domains for ML training seed data
# These help the model learn what ads look like even with no browsing history
KNOWN_AD_DOMAINS = [
    # Google Ads
    'pagead2.googlesyndication.com', 'googleadservices.com', 'doubleclick.net',
    'googleads.g.doubleclick.net', 'www.googleadservices.com', 'adservice.google.com',
    'tpc.googlesyndication.com', 'www.googletagservices.com',
    # YouTube Ads (injected in streams)
    'r1---sn-aigllnez.googlevideo.com', 'r2---sn-aigllnez.googlevideo.com',
    'yt3.ggpht.com', 'i.ytimg.com', 'www.youtube.com/api/stats/ads',
    'www.youtube.com/pagead', 'www.youtube.com/ptracking',
    # Facebook/Meta Ads
    'pixel.facebook.com', 'an.facebook.com', 'www.facebook.com/tr',
    'connect.facebook.net', 'staticxx.facebook.com',
    # Twitter/X Ads
    'ads-twitter.com', 'analytics.twitter.com', 't.co',
    # Amazon Ads
    'aax.amazon-adsystem.com', 'fls-na.amazon-adsystem.com',
    # Microsoft/Bing Ads
    'bat.bing.com', 'c.bing.com', 'a.ads.msn.com',
    # Other major ad networks
    'cdn.taboola.com', 'trc.taboola.com',
    'widgets.outbrain.com', 'log.outbrain.com',
    'ads.pubmatic.com', 'image6.pubmatic.com',
    'ib.adnxs.com', 'prebid.adnxs.com',
    'sync.sharethis.com', 'l.sharethis.com',
    'static.criteo.net', 'dis.criteo.com',
    'pixel.quantserve.com', 'edge.quantserve.com',
    'sb.scorecardresearch.com', 'b.scorecardresearch.com',
    'www.summerhamster.com', 'loadus.exelator.com',
    # Tracking pixels
    'track.hubspot.com', 'forms.hubspot.com',
    'pixel.advertising.com', 'pixel.rubiconproject.com',
    'beacon.krxd.net', 'cdn.krxd.net',
    # Mobile ad networks
    'app.adjust.com', 'app-measurement.com',
    'settings.crashlytics.com', 'app.appsflyer.com',
    # Analytics (often used for tracking)
    'ssl.google-analytics.com', 'www.google-analytics.com',
    'cdn.segment.com', 'api.segment.io',
    'cdn.amplitude.com', 'api.amplitude.com',
    'cdn.mxpnl.com', 'api.mixpanel.com',
    # Malicious/suspicious patterns (DGA-like)
    'xkcd93jd82.xyz', 'asjd83jd.top', 'dk3j9dk.click', '8fjd9dk3.work',
    'randomdomain123456.tk', 'suspicious-site-test.ml',
]

# Known safe/legitimate domains for training baseline
KNOWN_SAFE_DOMAINS = [
    # Major websites (definitely not ads)
    'www.google.com', 'www.youtube.com', 'www.github.com', 'www.stackoverflow.com',
    'www.wikipedia.org', 'www.reddit.com', 'www.amazon.com', 'www.netflix.com',
    'www.microsoft.com', 'www.apple.com', 'www.cloudflare.com',
    # CDNs (legitimate content delivery)
    'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com',
    # APIs (legitimate services)
    'api.github.com', 'api.stripe.com', 'api.twilio.com',
    # Email services
    'smtp.gmail.com', 'imap.gmail.com', 'outlook.office365.com',
    # Common infrastructure
    'dns.google', 'cloudflare-dns.com', '1.1.1.1', '8.8.8.8',
]

# Known tracker CNAME patterns (for uncloaking)
KNOWN_TRACKER_CNAMES = {
    'doubleclick.net': 'Google Ads',
    'googlesyndication.com': 'Google Ads',
    'googleadservices.com': 'Google Ads',
    'facebook.com': 'Facebook Tracking',
    'facebook.net': 'Facebook Tracking',
    'fbcdn.net': 'Facebook CDN',
    'analytics.google.com': 'Google Analytics',
    'google-analytics.com': 'Google Analytics',
    'criteo.com': 'Criteo Ads',
    'criteo.net': 'Criteo Ads',
    'taboola.com': 'Taboola',
    'outbrain.com': 'Outbrain',
    'branch.io': 'Branch Tracking',
    'adjust.com': 'Adjust Analytics',
    'appsflyer.com': 'AppsFlyer',
    'amplitude.com': 'Amplitude Analytics',
    'mixpanel.com': 'Mixpanel',
    'segment.io': 'Segment',
    'segment.com': 'Segment',
    'optimizely.com': 'Optimizely',
    'hotjar.com': 'Hotjar',
    'mouseflow.com': 'Mouseflow',
    'fullstory.com': 'FullStory',
    'newrelic.com': 'New Relic',
    'nr-data.net': 'New Relic',
    'scorecardresearch.com': 'ComScore',
    'quantserve.com': 'Quantcast',
    'omtrdc.net': 'Adobe Analytics',
    'demdex.net': 'Adobe Audience Manager',
    'adsrvr.org': 'The Trade Desk',
    'rubiconproject.com': 'Rubicon',
    'pubmatic.com': 'PubMatic',
    'openx.net': 'OpenX',
    'casalemedia.com': 'Index Exchange',
    'adnxs.com': 'AppNexus',
}

# Suspicious TLDs often used for malware/phishing
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'work', 'click', 'loan', 'win', 'gq', 'ml', 'cf', 'ga', 'tk',
    'buzz', 'icu', 'online', 'site', 'club', 'live', 'info', 'pw', 'cc', 'su',
    'download', 'stream', 'racing', 'review', 'country', 'science', 'party',
    'date', 'faith', 'accountant', 'cricket', 'webcam', 'bid', 'trade'
}

# Common safe TLDs
SAFE_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'co', 'io', 'dev',
    'app', 'ai', 'uk', 'de', 'fr', 'jp', 'au', 'ca', 'nz', 'eu'
}


class DomainFeatureExtractor:
    """Extract features from domain names for ML classification."""

    # Character sets
    VOWELS = set('aeiouAEIOU')
    CONSONANTS = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
    DIGITS = set('0123456789')

    @staticmethod
    def extract_features(domain: str) -> Dict[str, float]:
        """Extract numerical features from a domain name."""
        # Clean domain
        domain = domain.lower().strip('.')
        parts = domain.split('.')

        # Base domain (without TLD)
        if len(parts) > 1:
            base_domain = '.'.join(parts[:-1])
            tld = parts[-1]
        else:
            base_domain = domain
            tld = ''

        # Primary domain (second-level)
        primary = parts[-2] if len(parts) >= 2 else parts[0]

        features = {
            # Length features
            'length': len(domain),
            'primary_length': len(primary),
            'subdomain_count': max(0, len(parts) - 2),

            # Character composition
            'digit_ratio': sum(1 for c in primary if c in DomainFeatureExtractor.DIGITS) / max(len(primary), 1),
            'vowel_ratio': sum(1 for c in primary if c in DomainFeatureExtractor.VOWELS) / max(len(primary), 1),
            'consonant_ratio': sum(1 for c in primary if c in DomainFeatureExtractor.CONSONANTS) / max(len(primary), 1),
            'special_char_count': sum(1 for c in primary if c not in 'abcdefghijklmnopqrstuvwxyz0123456789-'),

            # Entropy (randomness measure)
            'entropy': DomainFeatureExtractor._calculate_entropy(primary),

            # N-gram features
            'consecutive_consonants': DomainFeatureExtractor._max_consecutive(primary, DomainFeatureExtractor.CONSONANTS),
            'consecutive_digits': DomainFeatureExtractor._max_consecutive(primary, DomainFeatureExtractor.DIGITS),

            # TLD features
            'suspicious_tld': 1.0 if tld in SUSPICIOUS_TLDS else 0.0,
            'safe_tld': 1.0 if tld in SAFE_TLDS else 0.0,

            # Pattern detection
            'has_hyphen': 1.0 if '-' in primary else 0.0,
            'hyphen_count': primary.count('-'),
            'digit_prefix': 1.0 if primary and primary[0].isdigit() else 0.0,
            'digit_suffix': 1.0 if primary and primary[-1].isdigit() else 0.0,

            # Lexical features
            'unique_chars': len(set(primary)) / max(len(primary), 1),
            'char_diversity': len(set(primary)),

            # DGA detection features
            'dga_score': DomainFeatureExtractor._dga_score(primary),
        }

        return features

    @staticmethod
    def _calculate_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0

        freq = Counter(s)
        length = len(s)
        entropy = 0.0

        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def _max_consecutive(s: str, char_set: set) -> int:
        """Find maximum consecutive characters from a set."""
        max_count = 0
        current = 0

        for c in s:
            if c in char_set:
                current += 1
                max_count = max(max_count, current)
            else:
                current = 0

        return max_count

    @staticmethod
    def _dga_score(domain: str) -> float:
        """Score likelihood of being a DGA (Domain Generation Algorithm) domain."""
        if not domain:
            return 0.0

        score = 0.0

        # High entropy suggests randomness
        entropy = DomainFeatureExtractor._calculate_entropy(domain)
        if entropy > 3.5:
            score += 0.3
        if entropy > 4.0:
            score += 0.2

        # Long domains with few vowels
        vowel_ratio = sum(1 for c in domain if c in 'aeiou') / len(domain)
        if len(domain) > 12 and vowel_ratio < 0.2:
            score += 0.3

        # Looks like random hex
        hex_ratio = sum(1 for c in domain if c in '0123456789abcdef') / len(domain)
        if hex_ratio > 0.8 and len(domain) > 10:
            score += 0.4

        # Many consecutive consonants
        if DomainFeatureExtractor._max_consecutive(domain, DomainFeatureExtractor.CONSONANTS) > 5:
            score += 0.2

        return min(score, 1.0)

    @staticmethod
    def to_vector(features: Dict[str, float]) -> List[float]:
        """Convert feature dict to ordered vector for ML model."""
        feature_order = [
            'length', 'primary_length', 'subdomain_count',
            'digit_ratio', 'vowel_ratio', 'consonant_ratio', 'special_char_count',
            'entropy', 'consecutive_consonants', 'consecutive_digits',
            'suspicious_tld', 'safe_tld', 'has_hyphen', 'hyphen_count',
            'digit_prefix', 'digit_suffix', 'unique_chars', 'char_diversity',
            'dga_score'
        ]
        return [features.get(f, 0.0) for f in feature_order]


class DNSMLClassifier:
    """ML-based domain classifier with anomaly detection."""

    def __init__(self):
        self.model = None
        self.scaler = None
        self.is_trained = False
        self.training_samples = 0
        self.last_trained = None
        self.feature_extractor = DomainFeatureExtractor()
        self._lock = threading.Lock()

        # Ensure ML directory exists
        os.makedirs(ML_DATA_DIR, exist_ok=True)

        # Load existing model if available
        self._load_model()

    def _load_model(self):
        """Load trained model from disk."""
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
                if HAS_SKLEARN:
                    self.model = joblib.load(MODEL_PATH)
                    self.scaler = joblib.load(SCALER_PATH)
                    self.is_trained = True

                    # Load metadata
                    meta_path = f'{ML_DATA_DIR}/model_meta.json'
                    if os.path.exists(meta_path):
                        with open(meta_path, 'r') as f:
                            meta = json.load(f)
                            self.training_samples = meta.get('samples', 0)
                            self.last_trained = meta.get('last_trained')

                    logger.info(f"Loaded ML model with {self.training_samples} training samples")
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")

    def _save_model(self):
        """Save trained model to disk."""
        try:
            if HAS_SKLEARN and self.model and self.scaler:
                joblib.dump(self.model, MODEL_PATH)
                joblib.dump(self.scaler, SCALER_PATH)

                # Save metadata
                meta = {
                    'samples': self.training_samples,
                    'last_trained': datetime.now().isoformat(),
                    'model_type': 'IsolationForest',
                    'version': '1.0'
                }
                with open(f'{ML_DATA_DIR}/model_meta.json', 'w') as f:
                    json.dump(meta, f)

                logger.info("Saved ML model to disk")
        except Exception as e:
            logger.error(f"Failed to save ML model: {e}")

    def train(self, domains: List[str], labels: Optional[List[int]] = None,
              use_seed_data: bool = True) -> Dict[str, Any]:
        """
        Train the classifier on domain data.

        Args:
            domains: List of domain names from user browsing
            labels: Optional labels (1=safe, -1=malicious). If None, uses unsupervised learning.
            use_seed_data: Whether to include known ad/safe domains for better training

        Returns:
            Training result with stats
        """
        if not HAS_SKLEARN or not HAS_NUMPY:
            return {
                'success': False,
                'error': 'ML libraries not installed (numpy, scikit-learn required)'
            }

        # Add seed data to improve training
        training_domains = list(domains) if domains else []
        seed_count = 0

        if use_seed_data:
            # Add known ad/tracking domains (these are "anomalies" we want to detect)
            training_domains.extend(KNOWN_AD_DOMAINS)
            seed_count += len(KNOWN_AD_DOMAINS)

            # Add known safe domains (baseline for "normal" behavior)
            training_domains.extend(KNOWN_SAFE_DOMAINS)
            seed_count += len(KNOWN_SAFE_DOMAINS)

            logger.info(f"Added {seed_count} seed domains for training")

        if len(training_domains) < 10:
            return {
                'success': False,
                'error': f'Need at least 10 domains for training (found {len(training_domains)}). '
                         f'Browse some websites first, or enable seed data.'
            }

        with self._lock:
            try:
                # Extract features
                feature_vectors = []
                valid_domains = []

                for domain in training_domains:
                    try:
                        features = self.feature_extractor.extract_features(domain)
                        vector = self.feature_extractor.to_vector(features)
                        feature_vectors.append(vector)
                        valid_domains.append(domain)
                    except Exception:
                        continue

                if len(feature_vectors) < 10:
                    return {
                        'success': False,
                        'error': 'Not enough valid domains for training'
                    }

                X = np.array(feature_vectors)

                # Scale features
                self.scaler = StandardScaler()
                X_scaled = self.scaler.fit_transform(X)

                # Calculate contamination based on known ad ratio
                # If we have seed data, we know roughly how many are ads
                if use_seed_data and seed_count > 0:
                    ad_ratio = len(KNOWN_AD_DOMAINS) / len(valid_domains)
                    contamination = min(0.3, max(0.05, ad_ratio))  # Between 5-30%
                else:
                    contamination = 0.1

                # Train Isolation Forest (anomaly detection)
                self.model = IsolationForest(
                    n_estimators=100,
                    contamination=contamination,
                    random_state=42,
                    n_jobs=-1
                )
                self.model.fit(X_scaled)

                self.is_trained = True
                self.training_samples = len(valid_domains)
                self.last_trained = datetime.now().isoformat()

                # Save model
                self._save_model()

                # Save training data for federated learning
                self._save_training_data(valid_domains)

                # Calculate user vs seed breakdown
                user_domains = len(domains) if domains else 0

                return {
                    'success': True,
                    'samples_trained': len(valid_domains),
                    'user_domains': user_domains,
                    'seed_domains': seed_count,
                    'features': X.shape[1],
                    'model_type': 'IsolationForest',
                    'contamination': round(contamination, 3),
                    'last_trained': self.last_trained
                }

            except Exception as e:
                logger.error(f"Training failed: {e}")
                return {
                    'success': False,
                    'error': str(e)
                }

    def _save_training_data(self, domains: List[str]):
        """Save anonymized training data for federated learning."""
        try:
            # Hash domains for privacy
            hashed = [hashlib.sha256(d.encode()).hexdigest()[:16] for d in domains]

            data = {
                'timestamp': datetime.now().isoformat(),
                'count': len(domains),
                'domain_hashes': hashed[:100]  # Limit stored hashes
            }

            with open(TRAINING_DATA_PATH, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logger.error(f"Failed to save training data: {e}")

    def predict(self, domain: str) -> Dict[str, Any]:
        """
        Classify a domain and return threat assessment.

        Returns:
            Dict with classification result, confidence, and features
        """
        result = {
            'domain': domain,
            'classification': 'unknown',
            'confidence': 0.0,
            'threat_score': 0.0,
            'is_suspicious': False,
            'features': {},
            'reasons': []
        }

        try:
            # Extract features
            features = self.feature_extractor.extract_features(domain)
            result['features'] = features

            # Rule-based checks first
            rule_score, rule_reasons = self._rule_based_check(domain, features)
            result['reasons'].extend(rule_reasons)

            # ML prediction if model is trained
            ml_score = 0.0
            if self.is_trained and HAS_SKLEARN and HAS_NUMPY:
                vector = np.array([self.feature_extractor.to_vector(features)])
                scaled = self.scaler.transform(vector)

                # Isolation Forest returns -1 for anomalies, 1 for normal
                prediction = self.model.predict(scaled)[0]

                # Get anomaly score (lower = more anomalous)
                anomaly_score = self.model.decision_function(scaled)[0]

                # Convert to threat score (0-1, higher = more threatening)
                # Decision function typically ranges from -0.5 to 0.5
                ml_score = max(0, min(1, 0.5 - anomaly_score))

                if prediction == -1:
                    result['reasons'].append('ML detected anomalous pattern')

            # Combine scores (weighted)
            combined_score = 0.6 * rule_score + 0.4 * ml_score if self.is_trained else rule_score
            result['threat_score'] = round(combined_score, 3)

            # Calculate confidence
            if self.is_trained:
                # Higher confidence if both rule-based and ML agree
                agreement = 1.0 if (rule_score > 0.5) == (ml_score > 0.5) else 0.5
                result['confidence'] = round(0.7 * agreement + 0.3 * min(self.training_samples / 1000, 1.0), 2)
            else:
                result['confidence'] = 0.5  # Lower confidence without ML

            # Classify
            if combined_score > 0.7:
                result['classification'] = 'malicious'
                result['is_suspicious'] = True
            elif combined_score > 0.4:
                result['classification'] = 'suspicious'
                result['is_suspicious'] = True
            else:
                result['classification'] = 'safe'

        except Exception as e:
            logger.error(f"Prediction failed for {domain}: {e}")
            result['error'] = str(e)

        return result

    def _rule_based_check(self, domain: str, features: Dict[str, float]) -> Tuple[float, List[str]]:
        """Apply rule-based heuristics for domain classification."""
        score = 0.0
        reasons = []

        # High entropy (randomness)
        if features.get('entropy', 0) > 4.0:
            score += 0.3
            reasons.append(f"High entropy ({features['entropy']:.2f})")

        # DGA-like pattern
        if features.get('dga_score', 0) > 0.5:
            score += 0.3
            reasons.append("DGA-like pattern detected")

        # Suspicious TLD
        if features.get('suspicious_tld', 0) > 0:
            score += 0.2
            reasons.append("Suspicious TLD")

        # Very long domain
        if features.get('length', 0) > 50:
            score += 0.15
            reasons.append("Unusually long domain")

        # Many digits
        if features.get('digit_ratio', 0) > 0.4:
            score += 0.2
            reasons.append("High digit ratio")

        # Many subdomains
        if features.get('subdomain_count', 0) > 4:
            score += 0.15
            reasons.append("Many subdomains")

        # Few vowels (unpronounceable)
        if features.get('vowel_ratio', 0) < 0.15 and features.get('primary_length', 0) > 8:
            score += 0.2
            reasons.append("Low vowel ratio (unpronounceable)")

        return min(score, 1.0), reasons

    def get_status(self) -> Dict[str, Any]:
        """Get classifier status and stats."""
        return {
            'is_trained': self.is_trained,
            'training_samples': self.training_samples,
            'last_trained': self.last_trained,
            'ml_available': HAS_SKLEARN and HAS_NUMPY,
            'model_type': 'IsolationForest' if self.is_trained else None
        }


class CNAMEUncloaker:
    """Detect trackers hiding behind CNAME cloaking."""

    def __init__(self):
        self.cname_cache: Dict[str, Dict] = {}
        self.uncloaked_count = 0
        self._lock = threading.Lock()
        self._load_cache()

    def _load_cache(self):
        """Load CNAME cache from disk."""
        try:
            if os.path.exists(CNAME_CACHE_PATH):
                with open(CNAME_CACHE_PATH, 'r') as f:
                    data = json.load(f)
                    self.cname_cache = data.get('cache', {})
                    self.uncloaked_count = data.get('uncloaked_count', 0)
        except Exception as e:
            logger.error(f"Failed to load CNAME cache: {e}")

    def _save_cache(self):
        """Save CNAME cache to disk."""
        try:
            with open(CNAME_CACHE_PATH, 'w') as f:
                json.dump({
                    'cache': dict(list(self.cname_cache.items())[-1000:]),  # Keep last 1000
                    'uncloaked_count': self.uncloaked_count,
                    'updated': datetime.now().isoformat()
                }, f)
        except Exception as e:
            logger.error(f"Failed to save CNAME cache: {e}")

    def check_cname(self, domain: str, cname_target: str) -> Dict[str, Any]:
        """
        Check if a CNAME record is hiding a tracker.

        Args:
            domain: The original domain being queried
            cname_target: The CNAME target domain

        Returns:
            Detection result with tracker info
        """
        result = {
            'domain': domain,
            'cname_target': cname_target,
            'is_tracker': False,
            'tracker_name': None,
            'confidence': 0.0,
            'first_party': self._is_first_party(domain, cname_target)
        }

        # Check if CNAME target matches known trackers
        cname_lower = cname_target.lower()

        for tracker_domain, tracker_name in KNOWN_TRACKER_CNAMES.items():
            if tracker_domain in cname_lower:
                result['is_tracker'] = True
                result['tracker_name'] = tracker_name
                result['confidence'] = 0.95

                # This is CNAME cloaking if the original domain looks first-party
                if result['first_party']:
                    result['is_cloaked'] = True
                    with self._lock:
                        self.uncloaked_count += 1
                        self.cname_cache[domain] = {
                            'target': cname_target,
                            'tracker': tracker_name,
                            'detected': datetime.now().isoformat()
                        }
                        self._save_cache()

                break

        # Heuristic detection for unknown trackers
        if not result['is_tracker']:
            heuristic_result = self._heuristic_tracker_check(domain, cname_target)
            if heuristic_result['is_suspicious']:
                result['is_tracker'] = True
                result['tracker_name'] = 'Unknown Tracker (heuristic)'
                result['confidence'] = heuristic_result['confidence']
                result['heuristic_reasons'] = heuristic_result['reasons']

        return result

    def _is_first_party(self, domain: str, cname_target: str) -> bool:
        """Check if CNAME appears to be first-party (same organization)."""
        # Extract base domains
        domain_parts = domain.lower().split('.')
        target_parts = cname_target.lower().split('.')

        if len(domain_parts) < 2 or len(target_parts) < 2:
            return True

        # Compare second-level domains
        domain_base = '.'.join(domain_parts[-2:])
        target_base = '.'.join(target_parts[-2:])

        return domain_base == target_base

    def _heuristic_tracker_check(self, domain: str, cname_target: str) -> Dict[str, Any]:
        """Use heuristics to detect unknown trackers."""
        result = {
            'is_suspicious': False,
            'confidence': 0.0,
            'reasons': []
        }

        target_lower = cname_target.lower()

        # Check for tracking-related keywords
        tracking_keywords = [
            'track', 'pixel', 'beacon', 'analytics', 'metric', 'telemetry',
            'collect', 'insight', 'measure', 'stats', 'log', 'event',
            'conversion', 'attribution', 'tag', 'cdn', 'static', 'asset'
        ]

        for keyword in tracking_keywords:
            if keyword in target_lower:
                result['reasons'].append(f"Contains tracking keyword: {keyword}")
                result['confidence'] += 0.2

        # Different TLD often indicates third-party
        if not self._is_first_party(domain, cname_target):
            result['reasons'].append("Third-party domain")
            result['confidence'] += 0.3

        # Check for known CDN/tracking patterns
        cdn_patterns = [
            r'cdn\d*\.', r'static\d*\.', r'assets?\.',
            r'px\d*\.', r'tr\d*\.', r'c\d+\.'
        ]

        for pattern in cdn_patterns:
            if re.search(pattern, target_lower):
                result['reasons'].append(f"CDN/tracking pattern: {pattern}")
                result['confidence'] += 0.15

        result['confidence'] = min(result['confidence'], 0.85)
        result['is_suspicious'] = result['confidence'] > 0.5

        return result

    def get_stats(self) -> Dict[str, Any]:
        """Get CNAME uncloaking statistics."""
        return {
            'total_uncloaked': self.uncloaked_count,
            'cached_entries': len(self.cname_cache),
            'known_trackers': len(KNOWN_TRACKER_CNAMES)
        }


class FederatedLearningManager:
    """
    Privacy-preserving federated learning for threat intelligence sharing.
    Shares model updates, not raw data.
    """

    def __init__(self):
        self.local_updates: List[Dict] = []
        self.received_updates: List[Dict] = []
        self.node_id = self._generate_node_id()
        self._load_state()

    def _generate_node_id(self) -> str:
        """Generate a unique anonymous node ID."""
        try:
            # Use MAC address hash for consistent ID
            mac = ':'.join(['{:02x}'.format((hash('guardian') >> i) & 0xff) for i in range(0, 48, 8)])
            return hashlib.sha256(mac.encode()).hexdigest()[:16]
        except Exception:
            return hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]

    def _load_state(self):
        """Load federated learning state."""
        try:
            if os.path.exists(FEDERATED_PATH):
                with open(FEDERATED_PATH, 'r') as f:
                    data = json.load(f)
                    self.local_updates = data.get('local_updates', [])
                    self.received_updates = data.get('received_updates', [])
        except Exception as e:
            logger.error(f"Failed to load federated state: {e}")

    def _save_state(self):
        """Save federated learning state."""
        try:
            with open(FEDERATED_PATH, 'w') as f:
                json.dump({
                    'node_id': self.node_id,
                    'local_updates': self.local_updates[-100:],  # Keep last 100
                    'received_updates': self.received_updates[-100:],
                    'updated': datetime.now().isoformat()
                }, f)
        except Exception as e:
            logger.error(f"Failed to save federated state: {e}")

    def create_update(self, threat_data: Dict) -> Dict[str, Any]:
        """
        Create a federated learning update from local threat detection.
        Privacy-preserving: shares patterns, not raw domains.
        """
        update = {
            'node_id': self.node_id,
            'timestamp': datetime.now().isoformat(),
            'type': 'threat_pattern',
            'data': {
                # Share feature statistics, not raw domains
                'feature_means': threat_data.get('feature_means', {}),
                'threat_count': threat_data.get('count', 0),
                'detection_type': threat_data.get('type', 'unknown'),
                # Hash of domain pattern (not the actual domain)
                'pattern_hash': hashlib.sha256(
                    str(threat_data.get('pattern', '')).encode()
                ).hexdigest()[:16]
            }
        }

        self.local_updates.append(update)
        self._save_state()

        return update

    def apply_update(self, update: Dict) -> bool:
        """
        Apply a received federated update to local model.

        Args:
            update: Federated learning update from another node

        Returns:
            Success status
        """
        try:
            if update.get('node_id') == self.node_id:
                return False  # Skip own updates

            self.received_updates.append({
                **update,
                'received': datetime.now().isoformat()
            })
            self._save_state()

            # TODO: Actually apply update to model weights
            # This would involve model aggregation (FedAvg, etc.)

            return True
        except Exception as e:
            logger.error(f"Failed to apply federated update: {e}")
            return False

    def get_exportable_updates(self) -> List[Dict]:
        """Get local updates ready to share with other nodes."""
        return self.local_updates[-10:]  # Share last 10 updates

    def get_stats(self) -> Dict[str, Any]:
        """Get federated learning statistics."""
        return {
            'node_id': self.node_id,
            'local_updates': len(self.local_updates),
            'received_updates': len(self.received_updates),
            'federation_active': len(self.received_updates) > 0
        }


class RealTimeThreatDetector:
    """Real-time DNS query threat detection pipeline."""

    def __init__(self, classifier: DNSMLClassifier, uncloaker: CNAMEUncloaker):
        self.classifier = classifier
        self.uncloaker = uncloaker
        self.threat_log: List[Dict] = []
        self.stats = {
            'total_analyzed': 0,
            'threats_detected': 0,
            'ml_detections': 0,
            'cname_uncloaked': 0
        }
        self._lock = threading.Lock()
        self._load_stats()

    def _load_stats(self):
        """Load threat detection stats."""
        try:
            if os.path.exists(THREAT_LOG_PATH):
                with open(THREAT_LOG_PATH, 'r') as f:
                    data = json.load(f)
                    self.stats = data.get('stats', self.stats)
                    self.threat_log = data.get('recent_threats', [])
        except Exception as e:
            logger.error(f"Failed to load threat stats: {e}")

    def _save_stats(self):
        """Save threat detection stats."""
        try:
            with open(THREAT_LOG_PATH, 'w') as f:
                json.dump({
                    'stats': self.stats,
                    'recent_threats': self.threat_log[-100:],
                    'updated': datetime.now().isoformat()
                }, f)
        except Exception as e:
            logger.error(f"Failed to save threat stats: {e}")

    def analyze_query(self, domain: str, query_type: str = 'A',
                      cname_chain: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Analyze a DNS query for threats in real-time.

        Args:
            domain: The queried domain
            query_type: DNS query type (A, AAAA, CNAME, etc.)
            cname_chain: Optional CNAME resolution chain

        Returns:
            Comprehensive threat analysis result
        """
        with self._lock:
            self.stats['total_analyzed'] += 1

        result = {
            'domain': domain,
            'query_type': query_type,
            'timestamp': datetime.now().isoformat(),
            'is_threat': False,
            'threat_type': None,
            'confidence': 0.0,
            'action': 'allow',
            'details': {}
        }

        # ML Classification
        ml_result = self.classifier.predict(domain)
        result['details']['ml_classification'] = ml_result

        if ml_result['is_suspicious']:
            result['is_threat'] = True
            result['threat_type'] = 'ml_detected'
            result['confidence'] = ml_result['confidence']
            result['action'] = 'block' if ml_result['threat_score'] > 0.7 else 'warn'

            with self._lock:
                self.stats['ml_detections'] += 1

        # CNAME Uncloaking
        if cname_chain:
            for cname in cname_chain:
                uncloak_result = self.uncloaker.check_cname(domain, cname)
                if uncloak_result['is_tracker']:
                    result['details']['cname_tracking'] = uncloak_result

                    if uncloak_result.get('is_cloaked'):
                        result['is_threat'] = True
                        result['threat_type'] = 'cname_cloaked_tracker'
                        result['confidence'] = max(result['confidence'], uncloak_result['confidence'])

                        with self._lock:
                            self.stats['cname_uncloaked'] += 1
                    break

        # Log threat if detected
        if result['is_threat']:
            with self._lock:
                self.stats['threats_detected'] += 1
                self.threat_log.append({
                    'domain': domain,
                    'type': result['threat_type'],
                    'confidence': result['confidence'],
                    'timestamp': result['timestamp']
                })

                # Periodic save
                if len(self.threat_log) % 10 == 0:
                    self._save_stats()

        return result

    def get_stats(self) -> Dict[str, Any]:
        """Get real-time detection statistics."""
        with self._lock:
            return {
                **self.stats,
                'classifier_status': self.classifier.get_status(),
                'uncloaker_stats': self.uncloaker.get_stats(),
                'recent_threats': self.threat_log[-10:]
            }


# Global instances (lazy initialization)
_classifier: Optional[DNSMLClassifier] = None
_uncloaker: Optional[CNAMEUncloaker] = None
_federated: Optional[FederatedLearningManager] = None
_detector: Optional[RealTimeThreatDetector] = None


def get_classifier() -> DNSMLClassifier:
    """Get the global ML classifier instance."""
    global _classifier
    if _classifier is None:
        _classifier = DNSMLClassifier()
    return _classifier


def get_uncloaker() -> CNAMEUncloaker:
    """Get the global CNAME uncloaker instance."""
    global _uncloaker
    if _uncloaker is None:
        _uncloaker = CNAMEUncloaker()
    return _uncloaker


def get_federated() -> FederatedLearningManager:
    """Get the global federated learning manager."""
    global _federated
    if _federated is None:
        _federated = FederatedLearningManager()
    return _federated


def get_detector() -> RealTimeThreatDetector:
    """Get the global real-time threat detector."""
    global _detector
    if _detector is None:
        _detector = RealTimeThreatDetector(get_classifier(), get_uncloaker())
    return _detector

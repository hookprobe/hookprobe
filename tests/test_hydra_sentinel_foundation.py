"""
Tests for HYDRA SENTINEL Foundation Modules
=============================================

Phase 1: baseline_profiler, cve_enricher, temporal_memory

Unit tests for core algorithms - no ClickHouse required.
"""

import math
import sys
import os
import pytest
from unittest.mock import patch, MagicMock
from collections import defaultdict

# Add core/hydra to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core', 'hydra'))


# ============================================================================
# BASELINE PROFILER TESTS
# ============================================================================

class TestWelfordAccumulator:
    """Test Welford's online algorithm for mean/variance."""

    def setup_method(self):
        from baseline_profiler import WelfordAccumulator
        self.Welford = WelfordAccumulator

    def test_empty_accumulator(self):
        w = self.Welford()
        assert w.count == 0
        assert w.mean == 0.0
        assert w.m2 == 0.0
        assert w.variance == 0.0
        assert w.stddev == 0.0

    def test_single_sample(self):
        w = self.Welford()
        w.update(5.0)
        assert w.count == 1
        assert w.mean == 5.0
        assert w.variance == 0.0  # Need >1 for variance

    def test_known_mean(self):
        w = self.Welford()
        values = [2.0, 4.0, 6.0, 8.0, 10.0]
        for v in values:
            w.update(v)
        assert w.count == 5
        assert abs(w.mean - 6.0) < 1e-10

    def test_known_variance(self):
        w = self.Welford()
        values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
        for v in values:
            w.update(v)
        # Population variance = E[(X - mean)^2]
        mean = sum(values) / len(values)
        pop_var = sum((x - mean) ** 2 for x in values) / len(values)
        assert abs(w.variance - pop_var) < 1e-10

    def test_z_score_at_mean(self):
        w = self.Welford()
        for v in [10.0, 20.0, 30.0, 40.0, 50.0]:
            w.update(v)
        z = w.z_score(w.mean)
        assert abs(z) < 1e-10

    def test_z_score_one_stddev(self):
        w = self.Welford()
        for v in [10.0, 20.0, 30.0, 40.0, 50.0]:
            w.update(v)
        z = w.z_score(w.mean + w.stddev)
        assert abs(z - 1.0) < 1e-10

    def test_z_score_zero_stddev(self):
        """Z-score should be 0 when stddev is 0 (all same values)."""
        w = self.Welford()
        for v in [5.0, 5.0, 5.0]:
            w.update(v)
        z = w.z_score(100.0)
        assert z == 0.0

    def test_restore_from_state(self):
        """Verify accumulator can be restored from stored state."""
        w1 = self.Welford()
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            w1.update(v)

        w2 = self.Welford(count=w1.count, mean=w1.mean, m2=w1.m2)
        assert w2.count == w1.count
        assert w2.mean == w1.mean
        assert abs(w2.variance - w1.variance) < 1e-10


class TestIPProfile:
    """Test per-IP statistical profiling."""

    def setup_method(self):
        from baseline_profiler import IPProfile, N_FEATURES
        self.IPProfile = IPProfile
        self.N_FEATURES = N_FEATURES

    def test_create_profile(self):
        p = self.IPProfile("1.2.3.4")
        assert p.ip == "1.2.3.4"
        assert p.window_count == 0
        assert len(p.features) == self.N_FEATURES

    def test_update_increments_window_count(self):
        p = self.IPProfile("1.2.3.4")
        vec = [float(i) for i in range(self.N_FEATURES)]
        p.update(vec, hour=10)
        assert p.window_count == 1

    def test_update_wrong_size_ignored(self):
        p = self.IPProfile("1.2.3.4")
        p.update([1.0, 2.0], hour=10)  # Wrong size
        assert p.window_count == 0

    def test_z_scores_shape(self):
        p = self.IPProfile("1.2.3.4")
        vec = [1.0] * self.N_FEATURES
        for _ in range(5):
            p.update(vec, hour=10)
        zs = p.z_scores(vec)
        assert len(zs) == self.N_FEATURES

    def test_diurnal_histogram(self):
        p = self.IPProfile("1.2.3.4")
        vec = [1.0] * self.N_FEATURES
        p.update(vec, hour=14)
        p.update(vec, hour=14)
        p.update(vec, hour=3)
        assert p.diurnal[14] == 2
        assert p.diurnal[3] == 1
        assert p.diurnal[0] == 0

    def test_max_abs_z(self):
        p = self.IPProfile("1.2.3.4")
        # Use varied baseline values so stddev > 0
        import random
        random.seed(42)
        for _ in range(20):
            vec = [10.0 + random.gauss(0, 2.0) for _ in range(self.N_FEATURES)]
            p.update(vec, hour=12)
        # Anomalous vector - first feature way off from mean
        anomalous = [10.0] * self.N_FEATURES
        anomalous[0] = 1000.0
        max_z = p.max_abs_z(anomalous)
        assert max_z > 5.0  # Should be highly anomalous


class TestLogisticRegression:
    """Test pure-Python logistic regression."""

    def setup_method(self):
        from baseline_profiler import LogisticRegression
        self.LR = LogisticRegression

    def test_initial_prediction(self):
        lr = self.LR(n_features=3)
        pred = lr.predict_proba([1.0, 2.0, 3.0])
        assert abs(pred - 0.5) < 0.01  # Untrained: sigmoid(0) = 0.5

    def test_train_separable_data(self):
        lr = self.LR(n_features=2, learning_rate=0.1, l2_lambda=0.0)
        # Simple linearly separable dataset
        X = [[0.0, 0.0], [0.1, 0.1], [0.2, 0.2],
             [0.8, 0.8], [0.9, 0.9], [1.0, 1.0]]
        y = [0, 0, 0, 1, 1, 1]
        lr.fit(X, y, epochs=200)
        # Should predict low for [0,0] and high for [1,1]
        assert lr.predict_proba([0.0, 0.0]) < 0.3
        assert lr.predict_proba([1.0, 1.0]) > 0.7


# ============================================================================
# CVE ENRICHER TESTS
# ============================================================================

class TestPortServiceMap:
    """Test port-to-service-to-CPE mapping."""

    def setup_method(self):
        from cve_enricher import PORT_SERVICE_MAP
        self.PORT_SERVICE_MAP = PORT_SERVICE_MAP

    def test_ssh_port_mapped(self):
        assert 22 in self.PORT_SERVICE_MAP
        vendors = [s['vendor'] for s in self.PORT_SERVICE_MAP[22]]
        assert 'openbsd' in vendors

    def test_http_port_mapped(self):
        assert 80 in self.PORT_SERVICE_MAP
        vendors = [s['vendor'] for s in self.PORT_SERVICE_MAP[80]]
        assert 'apache' in vendors
        assert 'nginx' in vendors

    def test_https_port_mapped(self):
        assert 443 in self.PORT_SERVICE_MAP

    def test_database_ports_mapped(self):
        assert 3306 in self.PORT_SERVICE_MAP  # MySQL
        assert 5432 in self.PORT_SERVICE_MAP  # PostgreSQL

    def test_rdp_port_mapped(self):
        assert 3389 in self.PORT_SERVICE_MAP

    def test_all_entries_have_required_fields(self):
        for port, services in self.PORT_SERVICE_MAP.items():
            for svc in services:
                assert 'vendor' in svc
                assert 'product' in svc
                assert 'service' in svc


class TestCveRelevanceScoring:
    """Test CVE relevance scoring computation."""

    def setup_method(self):
        import cve_enricher
        self.cve_enricher = cve_enricher

    def test_no_cves_returns_zero(self):
        # Empty cache should return zero relevance
        self.cve_enricher.port_cve_cache = {}
        result = self.cve_enricher.compute_cve_relevance(99999)
        assert result['cve_relevance_score'] == 0.0
        assert result['matched_cve_count'] == 0
        assert result['max_cvss_score'] == 0.0

    def test_with_cached_cves(self):
        self.cve_enricher.port_cve_cache = {
            22: [
                {
                    'cve_id': 'CVE-2024-0001',
                    'cvss_score': 9.8,
                    'attack_vector': 'NETWORK',
                    'attack_complexity': 'LOW',
                    'is_kev': 1,
                    'description': 'Critical SSH vuln',
                },
                {
                    'cve_id': 'CVE-2024-0002',
                    'cvss_score': 5.0,
                    'attack_vector': 'NETWORK',
                    'attack_complexity': 'HIGH',
                    'is_kev': 0,
                    'description': 'Medium SSH vuln',
                }
            ]
        }
        result = self.cve_enricher.compute_cve_relevance(22)
        assert result['matched_cve_count'] == 2
        assert result['max_cvss_score'] == 9.8
        assert result['has_kev'] is True or result['has_kev'] == 1
        assert result['cve_relevance_score'] > 0.0
        assert len(result['top_cve_ids']) <= 5

    def test_unknown_port_returns_zero(self):
        self.cve_enricher.port_cve_cache = {22: []}
        result = self.cve_enricher.compute_cve_relevance(12345)
        assert result['cve_relevance_score'] == 0.0


# ============================================================================
# TEMPORAL MEMORY TESTS
# ============================================================================

class TestDriftDetector:
    """Test KL divergence drift detection."""

    def setup_method(self):
        from temporal_memory import DriftDetector
        self.DriftDetector = DriftDetector

    def test_kl_divergence_identical(self):
        """KL divergence between identical distributions should be 0."""
        kl = self.DriftDetector.compute_kl_divergence(5.0, 1.0, 5.0, 1.0)
        assert abs(kl) < 1e-10

    def test_kl_divergence_different_means(self):
        """Different means should produce positive KL divergence."""
        kl = self.DriftDetector.compute_kl_divergence(0.0, 1.0, 10.0, 1.0)
        assert kl > 0.0

    def test_kl_divergence_different_variances(self):
        """Different variances should produce positive KL divergence."""
        kl = self.DriftDetector.compute_kl_divergence(5.0, 1.0, 5.0, 10.0)
        assert kl > 0.0

    def test_kl_divergence_symmetric(self):
        """Symmetric KL should give same result in both directions."""
        kl1 = self.DriftDetector.compute_kl_divergence(0.0, 1.0, 5.0, 2.0)
        kl2 = self.DriftDetector.compute_kl_divergence(5.0, 2.0, 0.0, 1.0)
        assert abs(kl1 - kl2) < 1e-10

    def test_kl_divergence_zero_variance_safe(self):
        """Should handle zero variance without crash."""
        kl = self.DriftDetector.compute_kl_divergence(5.0, 0.0, 5.0, 1.0)
        assert math.isfinite(kl)


class TestCampaignGraph:
    """Test campaign detection via co-occurrence graph."""

    def setup_method(self):
        from temporal_memory import CampaignGraph, CAMPAIGN_MIN_COOCCURRENCE
        self.CampaignGraph = CampaignGraph
        self.MIN_COOCCURRENCE = CAMPAIGN_MIN_COOCCURRENCE

    def test_empty_graph_no_campaigns(self):
        g = self.CampaignGraph()
        campaigns = g.detect_campaigns()
        assert campaigns == []

    def test_add_cooccurrence(self):
        g = self.CampaignGraph()
        g.edges['1.1.1.1']['2.2.2.2'] = 5
        g.edges['2.2.2.2']['1.1.1.1'] = 5
        assert g.edges['1.1.1.1']['2.2.2.2'] == 5

    def test_detect_campaign_strong_edges(self):
        g = self.CampaignGraph()
        # Create a group of IPs with strong co-occurrence
        ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3']
        for i, ip_a in enumerate(ips):
            for ip_b in ips[i + 1:]:
                g.edges[ip_a][ip_b] = self.MIN_COOCCURRENCE + 1
                g.edges[ip_b][ip_a] = self.MIN_COOCCURRENCE + 1
        campaigns = g.detect_campaigns()
        assert len(campaigns) >= 1
        # All 3 IPs should be in the same campaign
        first_campaign = campaigns[0]
        assert first_campaign['member_count'] == 3

    def test_weak_edges_no_campaign(self):
        g = self.CampaignGraph()
        g.edges['1.1.1.1']['2.2.2.2'] = 1  # Below threshold
        g.edges['2.2.2.2']['1.1.1.1'] = 1
        campaigns = g.detect_campaigns()
        assert len(campaigns) == 0

    def test_separate_campaigns(self):
        g = self.CampaignGraph()
        # Group A
        g.edges['10.0.0.1']['10.0.0.2'] = self.MIN_COOCCURRENCE + 1
        g.edges['10.0.0.2']['10.0.0.1'] = self.MIN_COOCCURRENCE + 1
        # Group B (disconnected from A)
        g.edges['20.0.0.1']['20.0.0.2'] = self.MIN_COOCCURRENCE + 1
        g.edges['20.0.0.2']['20.0.0.1'] = self.MIN_COOCCURRENCE + 1
        campaigns = g.detect_campaigns()
        assert len(campaigns) == 2

    def test_reputation_propagation(self):
        g = self.CampaignGraph()
        g.edges['1.1.1.1']['2.2.2.2'] = 5
        g.edges['2.2.2.2']['1.1.1.1'] = 5
        g.edges['2.2.2.2']['3.3.3.3'] = 5
        g.edges['3.3.3.3']['2.2.2.2'] = 5

        g.propagate_reputation('1.1.1.1', base_reputation=1.0)

        # Source should have full reputation
        assert g.reputation['1.1.1.1'] == 1.0
        # Direct neighbor should have decayed reputation
        assert '2.2.2.2' in g.reputation
        assert 0.0 < g.reputation['2.2.2.2'] < 1.0
        # 2-hop neighbor should have even less
        assert '3.3.3.3' in g.reputation
        assert g.reputation['3.3.3.3'] < g.reputation['2.2.2.2']

    def test_propagation_max_hops(self):
        """Reputation should not propagate beyond CAMPAIGN_MAX_HOPS."""
        from temporal_memory import CAMPAIGN_MAX_HOPS
        g = self.CampaignGraph()
        # Build a chain: ip0 -> ip1 -> ip2 -> ... -> ipN
        chain = [f'10.0.0.{i}' for i in range(CAMPAIGN_MAX_HOPS + 3)]
        for i in range(len(chain) - 1):
            g.edges[chain[i]][chain[i + 1]] = 10
            g.edges[chain[i + 1]][chain[i]] = 10

        g.propagate_reputation(chain[0], base_reputation=1.0)

        # IPs beyond max hops should have no reputation
        last_ip = chain[CAMPAIGN_MAX_HOPS + 2]
        assert g.reputation.get(last_ip, 0.0) == 0.0


class TestIntentTracker:
    """Test intent sequence tracking and entropy."""

    def setup_method(self):
        from temporal_memory import IntentTracker
        self.IntentTracker = IntentTracker

    def test_update_intent(self):
        tracker = self.IntentTracker()
        tracker.update('1.1.1.1', 'scan')
        # Should track the IP's last intent
        assert '1.1.1.1' in tracker.ip_last_intent

    def test_transition_counted(self):
        tracker = self.IntentTracker()
        tracker.update('1.1.1.1', 'scan')
        tracker.update('1.1.1.1', 'brute_force')
        # scan -> brute_force should be counted
        scan_idx = tracker.INTENT_IDX['scan']
        bf_idx = tracker.INTENT_IDX['brute_force']
        assert tracker.transitions[scan_idx][bf_idx] > 0

    def test_entropy_single_intent(self):
        """Single intent type should have zero entropy."""
        tracker = self.IntentTracker()
        for _ in range(10):
            tracker.update('1.1.1.1', 'scan')
        entropy = tracker.get_intent_entropy('1.1.1.1')
        assert entropy == 0.0

    def test_entropy_diverse_intents(self):
        """Multiple intent types should have positive entropy."""
        tracker = self.IntentTracker()
        intents = ['scan', 'brute_force', 'exploit', 'c2']
        for i, intent in enumerate(intents):
            tracker.update(f'1.1.1.{i}', intent)
            tracker.update('2.2.2.2', intent)

        # IP with diverse intents should have positive entropy
        entropy = tracker.get_intent_entropy('2.2.2.2')
        assert entropy > 0.0

    def test_unknown_ip_zero_entropy(self):
        tracker = self.IntentTracker()
        entropy = tracker.get_intent_entropy('99.99.99.99')
        assert entropy == 0.0

    def test_attack_chain_progression(self):
        """Test detection of classic attack chain: scan -> brute -> exploit -> c2."""
        tracker = self.IntentTracker()
        ip = '1.1.1.1'
        chain = ['scan', 'brute_force', 'exploit', 'c2']
        for intent in chain:
            tracker.update(ip, intent)

        # Should have 3 transitions recorded
        scan_idx = tracker.INTENT_IDX['scan']
        bf_idx = tracker.INTENT_IDX['brute_force']
        exploit_idx = tracker.INTENT_IDX['exploit']
        c2_idx = tracker.INTENT_IDX['c2']

        assert tracker.transitions[scan_idx][bf_idx] > 0
        assert tracker.transitions[bf_idx][exploit_idx] > 0
        assert tracker.transitions[exploit_idx][c2_idx] > 0


# ============================================================================
# FEATURE NAME CONSISTENCY TESTS
# ============================================================================

class TestFeatureConsistency:
    """Verify feature naming and count consistency across modules."""

    def test_baseline_profiler_feature_count(self):
        from baseline_profiler import N_FEATURES, FEATURE_NAMES
        assert N_FEATURES == len(FEATURE_NAMES)
        assert N_FEATURES == 12

    def test_baseline_profiler_feature_names(self):
        from baseline_profiler import FEATURE_NAMES
        expected = [
            'event_count', 'event_rate', 'unique_dst_ports', 'unique_protocols',
            'blocklist_ratio', 'syn_flag_ratio', 'dst_port_entropy',
            'flow_count', 'total_bytes', 'avg_flow_duration',
            'hour_sin', 'hour_cos',
        ]
        assert FEATURE_NAMES == expected

    def test_intent_classes_complete(self):
        from temporal_memory import IntentTracker
        # Verify all expected intent classes are present
        expected = {'scan', 'brute_force', 'exploit', 'ddos', 'c2', 'data_exfil', 'unknown'}
        actual = set(IntentTracker.INTENT_CLASSES)
        assert expected == actual


# ============================================================================
# MODULE IMPORT TESTS
# ============================================================================

class TestModuleImports:
    """Verify all three modules can be imported without errors."""

    def test_import_baseline_profiler(self):
        import baseline_profiler
        assert hasattr(baseline_profiler, 'WelfordAccumulator')
        assert hasattr(baseline_profiler, 'IPProfile')
        assert hasattr(baseline_profiler, 'LogisticRegression')

    def test_import_cve_enricher(self):
        import cve_enricher
        assert hasattr(cve_enricher, 'PORT_SERVICE_MAP')
        assert hasattr(cve_enricher, 'compute_cve_relevance')

    def test_import_temporal_memory(self):
        import temporal_memory
        assert hasattr(temporal_memory, 'DriftDetector')
        assert hasattr(temporal_memory, 'CampaignGraph')
        assert hasattr(temporal_memory, 'IntentTracker')

    def test_import_sentinel_engine(self):
        import sentinel_engine
        assert hasattr(sentinel_engine, 'GaussianFeature')
        assert hasattr(sentinel_engine, 'GaussianNaiveBayes')
        assert hasattr(sentinel_engine, 'IsotonicCalibrator')
        assert hasattr(sentinel_engine, 'SentinelEngine')
        assert hasattr(sentinel_engine, 'EVIDENCE_NAMES')


# ============================================================================
# SENTINEL ENGINE TESTS (Phase 2)
# ============================================================================

class TestGaussianFeature:
    """Test GaussianFeature Welford tracker for NB classifier."""

    def test_empty_state(self):
        from sentinel_engine import GaussianFeature
        gf = GaussianFeature()
        assert gf.count == 0
        assert gf.mean == 0.0
        assert gf.variance == 1.0  # Uninformed prior when count < 2

    def test_single_sample(self):
        from sentinel_engine import GaussianFeature
        gf = GaussianFeature()
        gf.update(5.0)
        assert gf.count == 1
        assert gf.mean == 5.0
        assert gf.variance == 1.0  # Still uninformed with count < 2

    def test_known_statistics(self):
        from sentinel_engine import GaussianFeature
        gf = GaussianFeature()
        # Known values: [2, 4, 6] -> mean=4, pop_variance=8/3
        for v in [2.0, 4.0, 6.0]:
            gf.update(v)
        assert gf.count == 3
        assert abs(gf.mean - 4.0) < 1e-10
        expected_var = 8.0 / 3.0  # population variance
        assert abs(gf.variance - expected_var) < 1e-10

    def test_log_likelihood(self):
        from sentinel_engine import GaussianFeature
        import math
        gf = GaussianFeature()
        for v in [0.0, 1.0, 2.0, 3.0, 4.0]:
            gf.update(v)
        # Mean = 2.0; log_likelihood at the mean should be highest
        ll_mean = gf.log_likelihood(2.0)
        ll_far = gf.log_likelihood(10.0)
        assert ll_mean > ll_far

    def test_non_finite_input_ignored(self):
        from sentinel_engine import GaussianFeature
        import math
        gf = GaussianFeature()
        gf.update(1.0)
        gf.update(float('inf'))
        gf.update(float('nan'))
        assert gf.count == 1  # Only the finite value counted

    def test_serialization_roundtrip(self):
        from sentinel_engine import GaussianFeature
        gf = GaussianFeature()
        for v in [1.0, 3.0, 5.0, 7.0]:
            gf.update(v)
        d = gf.to_dict()
        gf2 = GaussianFeature.from_dict(d)
        assert gf2.count == gf.count
        assert abs(gf2.mean - gf.mean) < 1e-10
        assert abs(gf2.m2 - gf.m2) < 1e-10


class TestGaussianNaiveBayes:
    """Test Gaussian Naive Bayes binary classifier."""

    def test_uninformed_prediction(self):
        from sentinel_engine import GaussianNaiveBayes
        gnb = GaussianNaiveBayes(5)
        # With no training data, predict_proba should return 0.5
        proba = gnb.predict_proba([0.0] * 5)
        assert abs(proba - 0.5) < 1e-10

    def test_wrong_feature_count_ignored(self):
        from sentinel_engine import GaussianNaiveBayes
        gnb = GaussianNaiveBayes(3)
        gnb.update([1.0, 2.0], True)  # Wrong size - should be ignored
        assert gnb.total_samples == 0

    def test_separable_data(self):
        from sentinel_engine import GaussianNaiveBayes
        gnb = GaussianNaiveBayes(2)
        # Positive class: high values
        for _ in range(20):
            gnb.update([8.0, 9.0], True)
        # Negative class: low values
        for _ in range(20):
            gnb.update([1.0, 2.0], False)

        assert gnb.total_samples == 40
        # High values should predict positive (TP)
        p_high = gnb.predict_proba([8.0, 9.0])
        assert p_high > 0.8
        # Low values should predict negative (FP)
        p_low = gnb.predict_proba([1.0, 2.0])
        assert p_low < 0.2

    def test_log_odds_sign(self):
        from sentinel_engine import GaussianNaiveBayes
        gnb = GaussianNaiveBayes(1)
        for _ in range(10):
            gnb.update([10.0], True)
            gnb.update([0.0], False)
        # log_odds for a positive-looking sample should be positive
        assert gnb.predict_log_odds([10.0]) > 0
        # log_odds for a negative-looking sample should be negative
        assert gnb.predict_log_odds([0.0]) < 0

    def test_serialization_roundtrip(self):
        from sentinel_engine import GaussianNaiveBayes
        gnb = GaussianNaiveBayes(3)
        for _ in range(5):
            gnb.update([1.0, 2.0, 3.0], True)
            gnb.update([7.0, 8.0, 9.0], False)
        d = gnb.to_dict()
        gnb2 = GaussianNaiveBayes.from_dict(d)
        assert gnb2.n_features == gnb.n_features
        assert gnb2.pos_count == gnb.pos_count
        assert gnb2.neg_count == gnb.neg_count
        # Predictions should match
        test_vec = [4.0, 5.0, 6.0]
        assert abs(gnb.predict_proba(test_vec) - gnb2.predict_proba(test_vec)) < 1e-10


class TestIsotonicCalibrator:
    """Test isotonic regression calibrator (PAVA)."""

    def test_passthrough_when_empty(self):
        from sentinel_engine import IsotonicCalibrator
        cal = IsotonicCalibrator()
        # No calibration data -> passthrough
        assert cal.calibrate(0.7) == 0.7

    def test_monotonic_output(self):
        from sentinel_engine import IsotonicCalibrator
        cal = IsotonicCalibrator()
        # Perfect calibration data: increasing scores = increasing labels
        scores = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
        labels = [0, 0, 0, 0, 1, 1, 1, 1, 1]
        cal.fit(scores, labels)
        # Output should be monotonically non-decreasing
        outputs = [cal.calibrate(s) for s in [0.1, 0.3, 0.5, 0.7, 0.9]]
        for i in range(len(outputs) - 1):
            assert outputs[i] <= outputs[i + 1] + 1e-10

    def test_calibration_range(self):
        from sentinel_engine import IsotonicCalibrator
        cal = IsotonicCalibrator()
        scores = [0.2, 0.4, 0.6, 0.8]
        labels = [0, 0, 1, 1]
        cal.fit(scores, labels)
        # Calibrated values should be in [0, 1]
        for s in [0.0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0]:
            c = cal.calibrate(s)
            assert 0.0 <= c <= 1.0

    def test_pava_violation_resolution(self):
        from sentinel_engine import IsotonicCalibrator
        cal = IsotonicCalibrator()
        # Data with violations: higher score sometimes has lower label
        scores = [0.1, 0.2, 0.3, 0.4, 0.5]
        labels = [0, 1, 0, 1, 1]  # Violation at index 2
        cal.fit(scores, labels)
        # PAVA should merge violated blocks
        assert cal.n_samples == 5
        # Result should still be monotonic
        outputs = [cal.calibrate(s) for s in [0.1, 0.2, 0.3, 0.4, 0.5]]
        for i in range(len(outputs) - 1):
            assert outputs[i] <= outputs[i + 1] + 1e-10

    def test_serialization_roundtrip(self):
        from sentinel_engine import IsotonicCalibrator
        cal = IsotonicCalibrator()
        cal.fit([0.1, 0.3, 0.5, 0.7, 0.9], [0, 0, 1, 1, 1])
        d = cal.to_dict()
        cal2 = IsotonicCalibrator.from_dict(d)
        assert cal2.n_samples == cal.n_samples
        assert len(cal2.bins) == len(cal.bins)
        assert abs(cal.calibrate(0.5) - cal2.calibrate(0.5)) < 1e-10


class TestRdapTypeScore:
    """Test RDAP type to threat prior mapping."""

    def test_known_types(self):
        from sentinel_engine import rdap_type_score
        assert rdap_type_score('tor_exit') == 0.85
        assert rdap_type_score('isp') == 0.25
        assert rdap_type_score('cdn') == 0.10

    def test_unknown_type(self):
        from sentinel_engine import rdap_type_score
        assert rdap_type_score('nonexistent') == 0.40

    def test_case_insensitive(self):
        from sentinel_engine import rdap_type_score
        assert rdap_type_score('TOR_EXIT') == 0.85
        assert rdap_type_score('VPN') == 0.70


class TestSentinelEnginePredict:
    """Test the SentinelEngine predict method."""

    def test_uninformed_prediction_is_heuristic(self):
        from sentinel_engine import SentinelEngine, N_EVIDENCE
        engine = SentinelEngine()
        # With no training, prediction should rely on heuristics only
        evidence = [0.0] * N_EVIDENCE
        result = engine.predict(evidence)
        assert 'sentinel_score' in result
        assert 'bayes_score' in result
        assert 'heuristic_score' in result
        assert 'verdict' in result
        assert 'confidence' in result
        # Uninformed Bayes should be 0.5
        assert abs(result['bayes_score'] - 0.5) < 1e-6

    def test_high_threat_evidence(self):
        from sentinel_engine import SentinelEngine, N_EVIDENCE
        engine = SentinelEngine()
        evidence = [0.0] * N_EVIDENCE
        # Set high threat signals
        evidence[1] = 0.85   # tor_exit RDAP type
        evidence[7] = 0.9    # high CVE relevance
        evidence[14] = 4.0   # high profile deviation (Z > 3)
        evidence[15] = 1.0   # in threat feed
        evidence[12] = 0.8   # high blocklist ratio
        result = engine.predict(evidence)
        assert result['sentinel_score'] > 0.4
        assert result['verdict'] in ('suspicious', 'malicious')

    def test_benign_evidence(self):
        from sentinel_engine import SentinelEngine, N_EVIDENCE
        engine = SentinelEngine()
        evidence = [0.0] * N_EVIDENCE
        evidence[1] = 0.10  # CDN RDAP type (very low threat)
        result = engine.predict(evidence)
        assert result['sentinel_score'] < 0.4
        assert result['verdict'] == 'benign'

    def test_verdict_thresholds(self):
        from sentinel_engine import SentinelEngine, N_EVIDENCE
        engine = SentinelEngine()
        # Verdict thresholds: malicious >= 0.7, suspicious >= 0.4, benign < 0.4
        # Test boundary by constructing result manually
        evidence = [0.0] * N_EVIDENCE
        result = engine.predict(evidence)
        score = result['sentinel_score']
        if score >= 0.7:
            assert result['verdict'] == 'malicious'
        elif score >= 0.4:
            assert result['verdict'] == 'suspicious'
        else:
            assert result['verdict'] == 'benign'

    def test_temporal_boost(self):
        from sentinel_engine import SentinelEngine, N_EVIDENCE
        engine = SentinelEngine()
        evidence = [0.0] * N_EVIDENCE
        evidence[1] = 0.40  # moderate RDAP

        # Score without temporal
        result_no_temporal = engine.predict(evidence)

        # Score with temporal signals
        temporal = {
            'drift_score': 5.0,
            'campaign_reputation': 0.5,
            'intent_entropy': 0.8,
            'diurnal_anomaly': 0.6,
        }
        result_with_temporal = engine.predict(evidence, temporal)

        # Temporal signals should boost the score
        assert result_with_temporal['sentinel_score'] > result_no_temporal['sentinel_score']


class TestSentinelEngineHeuristic:
    """Test the heuristic scoring component."""

    def test_heuristic_weights_sum_to_one(self):
        from sentinel_engine import SentinelEngine
        engine = SentinelEngine()
        total = (engine.hw_profile + engine.hw_cve + engine.hw_rdap +
                 engine.hw_feed + engine.hw_behavior)
        assert abs(total - 1.0) < 1e-10

    def test_heuristic_score_range(self):
        from sentinel_engine import SentinelEngine, N_EVIDENCE
        engine = SentinelEngine()
        # All zeros
        evidence = [0.0] * N_EVIDENCE
        h = engine._heuristic_score(evidence)
        assert 0.0 <= h <= 1.0

        # All maxed
        evidence = [1.0] * N_EVIDENCE
        evidence[3] = 5.0  # Z-scores can be higher
        evidence[5] = 5.0
        evidence[6] = 5.0
        evidence[14] = 5.0
        h = engine._heuristic_score(evidence)
        assert 0.0 <= h <= 1.0

    def test_temporal_boost_capped(self):
        from sentinel_engine import SentinelEngine, N_EVIDENCE
        engine = SentinelEngine()
        evidence = [1.0] * N_EVIDENCE
        evidence[14] = 5.0
        # Extreme temporal values
        temporal = {
            'drift_score': 100.0,
            'campaign_reputation': 1.0,
            'intent_entropy': 1.0,
            'diurnal_anomaly': 1.0,
        }
        h = engine._heuristic_score(evidence, temporal)
        assert h <= 1.0  # Must be capped


class TestSentinelEngineSerialization:
    """Test SentinelEngine serialization and model state persistence."""

    def test_engine_roundtrip(self):
        from sentinel_engine import SentinelEngine
        engine = SentinelEngine()
        engine.version = 5
        engine.last_trained = '2026-01-01T00:00:00'
        engine.w_bayes = 0.6
        engine.w_heuristic = 0.4

        d = engine.to_dict()
        engine2 = SentinelEngine.from_dict(d)
        assert engine2.version == 5
        assert engine2.last_trained == '2026-01-01T00:00:00'
        assert abs(engine2.w_bayes - 0.6) < 1e-10
        assert abs(engine2.w_heuristic - 0.4) < 1e-10

    def test_engine_with_trained_gnb_roundtrip(self):
        from sentinel_engine import SentinelEngine, N_EVIDENCE
        engine = SentinelEngine()
        # Train with some data
        for _ in range(15):
            pos_ev = [0.8] * N_EVIDENCE
            neg_ev = [0.2] * N_EVIDENCE
            engine.gnb.update(pos_ev, True)
            engine.gnb.update(neg_ev, False)

        d = engine.to_dict()
        engine2 = SentinelEngine.from_dict(d)
        assert engine2.gnb.total_samples == engine.gnb.total_samples

        # Predictions should match
        test_ev = [0.5] * N_EVIDENCE
        p1 = engine.predict(test_ev)
        p2 = engine2.predict(test_ev)
        assert abs(p1['sentinel_score'] - p2['sentinel_score']) < 1e-6


class TestEvidenceNames:
    """Test evidence feature vector configuration."""

    def test_evidence_count_is_20(self):
        from sentinel_engine import N_EVIDENCE, EVIDENCE_NAMES
        assert N_EVIDENCE == 20
        assert len(EVIDENCE_NAMES) == 20

    def test_key_feature_names(self):
        from sentinel_engine import EVIDENCE_NAMES
        assert EVIDENCE_NAMES[0] == 'if_score'
        assert EVIDENCE_NAMES[1] == 'rdap_type_score'
        assert EVIDENCE_NAMES[7] == 'cve_relevance'
        assert EVIDENCE_NAMES[14] == 'profile_deviation'
        assert EVIDENCE_NAMES[15] == 'in_threat_feed'
        assert EVIDENCE_NAMES[19] == 'bytes_ratio'

    def test_no_duplicate_names(self):
        from sentinel_engine import EVIDENCE_NAMES
        assert len(EVIDENCE_NAMES) == len(set(EVIDENCE_NAMES))


class TestVerdictDedup:
    """Test verdict deduplication logic."""

    def test_first_write_allowed(self):
        from sentinel_engine import _should_write_verdict, _verdict_dedup
        # Clear dedup state
        _verdict_dedup.clear()
        assert _should_write_verdict('192.168.1.1') is True

    def test_duplicate_blocked(self):
        from sentinel_engine import _should_write_verdict, _verdict_dedup
        _verdict_dedup.clear()
        _should_write_verdict('10.0.0.1')
        assert _should_write_verdict('10.0.0.1') is False

    def test_different_ips_independent(self):
        from sentinel_engine import _should_write_verdict, _verdict_dedup
        _verdict_dedup.clear()
        _should_write_verdict('10.0.0.1')
        assert _should_write_verdict('10.0.0.2') is True


class TestClampZ:
    """Test Z-score clamping utility."""

    def test_clamp_within_range(self):
        from sentinel_engine import _clamp_z
        assert _clamp_z(2.0) == 2.0

    def test_clamp_exceeds_upper(self):
        from sentinel_engine import _clamp_z
        assert _clamp_z(10.0) == 5.0

    def test_clamp_exceeds_lower(self):
        from sentinel_engine import _clamp_z
        assert _clamp_z(-10.0) == -5.0

    def test_clamp_non_finite(self):
        from sentinel_engine import _clamp_z
        import math
        assert _clamp_z(float('inf')) == 0.0
        assert _clamp_z(float('nan')) == 0.0

    def test_custom_limit(self):
        from sentinel_engine import _clamp_z
        assert _clamp_z(3.0, limit=2.0) == 2.0


# ============================================================================
# PHASE 3+4 TESTS: SENTINEL LIFECYCLE, HYDRA BRIDGE, UNIFIED ENGINE
# ============================================================================


class TestPageHinkleyDetector:
    """Test Page-Hinkley drift detection algorithm."""

    def setup_method(self):
        from sentinel_lifecycle import PageHinkleyDetector
        self.PHD = PageHinkleyDetector

    def test_initial_state(self):
        d = self.PHD(threshold=0.15)
        assert d.count == 0
        assert d.mean == 0.0
        assert d.cumsum == 0.0
        assert d.min_cumsum == 0.0
        assert d.drift_detected is False

    def test_stable_signal_no_drift(self):
        """Feeding a constant value should never trigger drift."""
        d = self.PHD(threshold=0.15, delta=0.005)
        for _ in range(100):
            result = d.update(0.3)
        assert result is False
        assert d.drift_detected is False
        assert d.count == 100

    def test_drift_on_mean_shift(self):
        """Feeding low values then high values should trigger drift."""
        d = self.PHD(threshold=0.10, delta=0.005)
        # Stable phase — low loss
        for _ in range(50):
            d.update(0.1)
        assert d.drift_detected is False

        # Shift phase — high loss
        triggered = False
        for _ in range(50):
            if d.update(0.9):
                triggered = True
                break
        assert triggered, "Expected drift detection after mean shift"

    def test_reset_clears_state(self):
        d = self.PHD(threshold=0.15)
        d.update(0.5)
        d.update(0.6)
        d.reset()
        assert d.count == 0
        assert d.sum_x == 0.0
        assert d.cumsum == 0.0
        assert d.min_cumsum == 0.0
        assert d.drift_detected is False

    def test_non_finite_ignored(self):
        d = self.PHD()
        d.update(0.5)
        result = d.update(float('nan'))
        assert result is False
        assert d.count == 1  # nan was skipped

        result2 = d.update(float('inf'))
        assert result2 is False
        assert d.count == 1

    def test_to_dict(self):
        d = self.PHD(delta=0.01, threshold=0.20)
        d.update(0.5)
        d.update(0.6)
        state = d.to_dict()
        assert state['delta'] == 0.01
        assert state['threshold'] == 0.20
        assert state['count'] == 2
        assert 'cumsum' in state
        assert 'min_cumsum' in state

    def test_mean_property(self):
        d = self.PHD()
        assert d.mean == 0.0
        d.update(4.0)
        assert d.mean == 4.0
        d.update(6.0)
        assert abs(d.mean - 5.0) < 1e-10


class TestFishersExactTest:
    """Test Fisher's exact test for A/B model promotion."""

    def setup_method(self):
        from sentinel_lifecycle import fishers_exact_one_sided
        self.fisher = fishers_exact_one_sided

    def test_empty_table_returns_1(self):
        assert self.fisher(0, 0, 0, 0) == 1.0

    def test_perfect_champion(self):
        """Champion 100% success, challenger 0% — strong signal."""
        p = self.fisher(10, 0, 0, 10)
        assert p < 0.001, f"Expected p < 0.001, got {p}"

    def test_equal_performance(self):
        """Equal success rates — p should be ~1.0."""
        p = self.fisher(5, 5, 5, 5)
        assert p > 0.3, f"Expected non-significant p, got {p}"

    def test_p_value_bounded(self):
        """P-value should always be in [0, 1]."""
        p = self.fisher(8, 2, 3, 7)
        assert 0.0 <= p <= 1.0

    def test_symmetric_case(self):
        """Champion slightly better but not significant."""
        p = self.fisher(6, 4, 4, 6)
        assert p > 0.05, f"Expected non-significant, got {p}"


class TestComputeMetrics:
    """Test classification metrics computation."""

    def setup_method(self):
        from sentinel_lifecycle import compute_metrics
        self.compute = compute_metrics

    def test_all_true_positives(self):
        decisions = [('malicious', 'confirm', 0.9)] * 10
        m = self.compute(decisions)
        assert m['tp'] == 10
        assert m['fp'] == 0
        assert m['fn'] == 0
        assert m['tn'] == 0
        assert m['precision'] == 1.0
        assert m['recall'] == 1.0
        assert m['f1_score'] == 1.0

    def test_all_false_positives(self):
        decisions = [('malicious', 'false_positive', 0.8)] * 5
        m = self.compute(decisions)
        assert m['tp'] == 0
        assert m['fp'] == 5
        assert m['precision'] == 0.0
        assert m['recall'] == 0.0

    def test_mixed_verdicts(self):
        decisions = [
            ('malicious', 'confirm', 0.9),        # TP
            ('malicious', 'false_positive', 0.7),  # FP
            ('suspicious', 'confirm', 0.5),        # TP
            ('benign', 'confirm', 0.1),            # TN
            ('benign', 'false_positive', 0.2),     # FN
        ]
        m = self.compute(decisions)
        assert m['tp'] == 2
        assert m['fp'] == 1
        assert m['fn'] == 1
        assert m['tn'] == 1
        assert m['total'] == 5
        # Precision = 2/3, Recall = 2/3
        assert abs(m['precision'] - 2 / 3) < 0.01
        assert abs(m['recall'] - 2 / 3) < 0.01

    def test_empty_decisions(self):
        m = self.compute([])
        assert m['total'] == 0
        assert m['precision'] == 0.0

    def test_benign_confirmed_is_tn(self):
        """Benign verdict + operator confirms = TN."""
        m = self.compute([('benign', 'confirm', 0.1)])
        assert m['tn'] == 1
        assert m['tp'] == 0

    def test_benign_false_positive_is_fn(self):
        """Benign verdict + operator says false positive = FN (model missed)."""
        m = self.compute([('benign', 'false_positive', 0.2)])
        assert m['fn'] == 1


class TestSentinelLifecycleState:
    """Test SentinelLifecycle initialization and state."""

    def setup_method(self):
        from sentinel_lifecycle import SentinelLifecycle
        self.Lifecycle = SentinelLifecycle

    def test_initial_state(self):
        lc = self.Lifecycle()
        assert lc.cycles == 0
        assert lc.champion_version == 0
        assert lc.ab_active is False
        assert lc.last_decision_count == 0
        assert isinstance(lc.drift_detector, object)

    def test_drift_detector_type(self):
        from sentinel_lifecycle import PageHinkleyDetector
        lc = self.Lifecycle()
        assert isinstance(lc.drift_detector, PageHinkleyDetector)

    def test_ab_results_initialized(self):
        lc = self.Lifecycle()
        assert lc.champion_results == [0, 0]
        assert lc.challenger_results == [0, 0]


class TestLogFactorial:
    """Test log-factorial helper used by Fisher's test."""

    def setup_method(self):
        from sentinel_lifecycle import _log_factorial
        self.logfact = _log_factorial

    def test_base_cases(self):
        assert self.logfact(0) == 0.0
        assert self.logfact(1) == 0.0

    def test_small_exact(self):
        """For n <= 20, should be exact."""
        assert abs(self.logfact(5) - math.log(120)) < 1e-10
        assert abs(self.logfact(10) - math.log(3628800)) < 1e-10

    def test_stirling_approximation(self):
        """For n > 20, uses Stirling's — should be close."""
        exact_20 = self.logfact(20)
        # log(20!) ≈ 42.3356
        assert abs(exact_20 - 42.3356) < 0.01

        # Stirling for n=25 should be reasonable
        val = self.logfact(25)
        assert val > 40  # log(25!) ≈ 58.0


# ============================================================================
# HYDRA BRIDGE TESTS
# ============================================================================

class TestHydraBridgePoll:
    """Test HydraBridge signal emission from cache file."""

    def _write_cache(self, tmp_path, data):
        import json
        cache_file = tmp_path / "sentinel_scores.json"
        cache_file.write_text(json.dumps(data))
        return str(cache_file)

    def test_no_file_returns_empty(self, tmp_path):
        from core.aegis.bridges.hydra_bridge import HydraBridge
        bridge = HydraBridge(str(tmp_path / "nonexistent.json"))
        signals = bridge.poll()
        assert signals == []

    def test_malicious_verdict_signal(self, tmp_path):
        from core.aegis.bridges.hydra_bridge import HydraBridge
        cache = self._write_cache(tmp_path, {
            "cycle": 1, "scored": 5,
            "verdicts": {"malicious": 1, "benign": 4},
            "malicious_ips": [
                {"ip": "1.2.3.4", "score": 0.85, "confidence": 0.7, "campaign_id": ""}
            ],
            "suspicious_ips": [],
            "drift_detected": False,
            "model_version": 1,
        })
        bridge = HydraBridge(cache)
        signals = bridge.poll()
        assert len(signals) == 1
        assert signals[0].source == "hydra"
        assert signals[0].event_type == "verdict.malicious"
        assert signals[0].severity == "HIGH"
        assert signals[0].data["ip"] == "1.2.3.4"

    def test_suspicious_verdict_signal(self, tmp_path):
        from core.aegis.bridges.hydra_bridge import HydraBridge
        cache = self._write_cache(tmp_path, {
            "cycle": 1, "scored": 3,
            "verdicts": {"suspicious": 1, "benign": 2},
            "malicious_ips": [],
            "suspicious_ips": [
                {"ip": "5.6.7.8", "score": 0.55, "confidence": 0.4}
            ],
            "drift_detected": False,
            "model_version": 1,
        })
        bridge = HydraBridge(cache)
        signals = bridge.poll()
        assert len(signals) == 1
        assert signals[0].event_type == "verdict.suspicious"
        assert signals[0].severity == "MEDIUM"

    def test_campaign_signal_on_first_malicious(self, tmp_path):
        from core.aegis.bridges.hydra_bridge import HydraBridge
        cache = self._write_cache(tmp_path, {
            "cycle": 1, "scored": 2,
            "verdicts": {"malicious": 1},
            "malicious_ips": [
                {"ip": "10.0.0.1", "score": 0.9, "confidence": 0.8, "campaign_id": "C-10.0.0.1-3"}
            ],
            "suspicious_ips": [],
            "drift_detected": False,
            "model_version": 1,
        })
        bridge = HydraBridge(cache)
        signals = bridge.poll()
        # Should have verdict.malicious + campaign_detected
        types = [s.event_type for s in signals]
        assert "verdict.malicious" in types
        assert "campaign_detected" in types
        campaign = [s for s in signals if s.event_type == "campaign_detected"][0]
        assert campaign.data["campaign_id"] == "C-10.0.0.1-3"

    def test_campaign_dedup_on_second_cycle(self, tmp_path):
        """Same malicious IP in second cycle should NOT re-emit campaign signal."""
        from core.aegis.bridges.hydra_bridge import HydraBridge
        cache_file = tmp_path / "sentinel_scores.json"
        import json, time

        # Cycle 1
        cache_file.write_text(json.dumps({
            "cycle": 1, "scored": 1,
            "verdicts": {"malicious": 1},
            "malicious_ips": [
                {"ip": "10.0.0.1", "score": 0.9, "confidence": 0.8, "campaign_id": "C-10.0.0.1-3"}
            ],
            "suspicious_ips": [],
            "drift_detected": False,
            "model_version": 1,
        }))
        bridge = HydraBridge(str(cache_file))
        s1 = bridge.poll()
        campaign_count_1 = sum(1 for s in s1 if s.event_type == "campaign_detected")

        # Cycle 2 — same IP, bump mtime
        time.sleep(0.05)
        cache_file.write_text(json.dumps({
            "cycle": 2, "scored": 1,
            "verdicts": {"malicious": 1},
            "malicious_ips": [
                {"ip": "10.0.0.1", "score": 0.9, "confidence": 0.8, "campaign_id": "C-10.0.0.1-3"}
            ],
            "suspicious_ips": [],
            "drift_detected": False,
            "model_version": 1,
        }))
        s2 = bridge.poll()
        campaign_count_2 = sum(1 for s in s2 if s.event_type == "campaign_detected")

        assert campaign_count_1 == 1
        assert campaign_count_2 == 0  # Deduped

    def test_drift_signal_on_edge(self, tmp_path):
        from core.aegis.bridges.hydra_bridge import HydraBridge
        cache = self._write_cache(tmp_path, {
            "cycle": 1, "scored": 5,
            "verdicts": {"benign": 5},
            "malicious_ips": [],
            "suspicious_ips": [],
            "drift_detected": True,
            "model_version": 1,
        })
        bridge = HydraBridge(cache)
        signals = bridge.poll()
        drift_signals = [s for s in signals if s.event_type == "drift_detected"]
        assert len(drift_signals) == 1
        assert drift_signals[0].severity == "MEDIUM"

    def test_drift_not_repeated(self, tmp_path):
        """Drift should only fire once (edge-triggered, not level-triggered)."""
        from core.aegis.bridges.hydra_bridge import HydraBridge
        import json, time
        cache_file = tmp_path / "sentinel_scores.json"

        base = {"scored": 5, "verdicts": {"benign": 5},
                "malicious_ips": [], "suspicious_ips": [],
                "drift_detected": True, "model_version": 1}

        base["cycle"] = 1
        cache_file.write_text(json.dumps(base))
        bridge = HydraBridge(str(cache_file))
        s1 = bridge.poll()
        d1 = sum(1 for s in s1 if s.event_type == "drift_detected")

        time.sleep(0.05)
        base["cycle"] = 2
        cache_file.write_text(json.dumps(base))
        s2 = bridge.poll()
        d2 = sum(1 for s in s2 if s.event_type == "drift_detected")

        assert d1 == 1
        assert d2 == 0  # Already seen drift=True

    def test_model_retrained_signal(self, tmp_path):
        from core.aegis.bridges.hydra_bridge import HydraBridge
        import json, time
        cache_file = tmp_path / "sentinel_scores.json"

        # Cycle 1 — establish version 3
        cache_file.write_text(json.dumps({
            "cycle": 1, "scored": 0, "verdicts": {},
            "malicious_ips": [], "suspicious_ips": [],
            "drift_detected": False, "model_version": 3,
        }))
        bridge = HydraBridge(str(cache_file))
        s1 = bridge.poll()
        # First cycle: no retrain signal (need prior version)
        retrain_1 = [s for s in s1 if s.event_type == "model_retrained"]
        assert len(retrain_1) == 0

        # Cycle 2 — version bumped to 4
        time.sleep(0.05)
        cache_file.write_text(json.dumps({
            "cycle": 2, "scored": 0, "verdicts": {},
            "malicious_ips": [], "suspicious_ips": [],
            "drift_detected": False, "model_version": 4,
        }))
        s2 = bridge.poll()
        retrain_2 = [s for s in s2 if s.event_type == "model_retrained"]
        assert len(retrain_2) == 1
        assert retrain_2[0].data["old_version"] == 3
        assert retrain_2[0].data["new_version"] == 4

    def test_same_cycle_skipped(self, tmp_path):
        """Same cycle number with different mtime should be skipped."""
        from core.aegis.bridges.hydra_bridge import HydraBridge
        import json, time
        cache_file = tmp_path / "sentinel_scores.json"

        cache_file.write_text(json.dumps({
            "cycle": 5, "scored": 1,
            "verdicts": {"malicious": 1},
            "malicious_ips": [{"ip": "1.1.1.1", "score": 0.8, "confidence": 0.6, "campaign_id": ""}],
            "suspicious_ips": [],
            "drift_detected": False, "model_version": 1,
        }))
        bridge = HydraBridge(str(cache_file))
        s1 = bridge.poll()
        assert len(s1) == 1

        # Re-write with same cycle
        time.sleep(0.05)
        cache_file.write_text(json.dumps({
            "cycle": 5, "scored": 1,
            "verdicts": {"malicious": 1},
            "malicious_ips": [{"ip": "2.2.2.2", "score": 0.9, "confidence": 0.7, "campaign_id": ""}],
            "suspicious_ips": [],
            "drift_detected": False, "model_version": 1,
        }))
        s2 = bridge.poll()
        assert len(s2) == 0  # Same cycle — skipped


# ============================================================================
# UNIFIED ENGINE SENTINEL WEIGHT TESTS
# ============================================================================

class TestUnifiedEngineConfigSentinel:
    """Test SENTINEL weight in UnifiedEngineConfig."""

    def setup_method(self):
        from core.qsecbit.unified_engine import UnifiedEngineConfig, DeploymentType
        self.Config = UnifiedEngineConfig
        self.DT = DeploymentType

    def test_guardian_sentinel_zero(self):
        cfg = self.Config(deployment_type=self.DT.GUARDIAN)
        weights = cfg.get_weights()
        assert weights['sentinel'] == 0.0

    def test_fortress_sentinel_nonzero(self):
        cfg = self.Config(deployment_type=self.DT.FORTRESS)
        weights = cfg.get_weights()
        assert weights['sentinel'] > 0.10
        assert weights['sentinel'] < 0.20

    def test_nexus_sentinel_highest(self):
        cfg = self.Config(deployment_type=self.DT.NEXUS)
        weights = cfg.get_weights()
        assert weights['sentinel'] > 0.15

    def test_custom_sentinel_weight_override(self):
        cfg = self.Config(deployment_type=self.DT.FORTRESS, sentinel_weight=0.25)
        weights = cfg.get_weights()
        # After normalization, sentinel should be dominant
        assert weights['sentinel'] > 0.20

    def test_weights_sum_to_one(self):
        """All deployment types should have weights summing to 1.0."""
        for dt in self.DT:
            cfg = self.Config(deployment_type=dt)
            weights = cfg.get_weights()
            total = sum(weights.values())
            assert abs(total - 1.0) < 1e-10, f"{dt.value}: weights sum to {total}"

    def test_sentinel_key_present_in_all(self):
        for dt in self.DT:
            cfg = self.Config(deployment_type=dt)
            weights = cfg.get_weights()
            assert 'sentinel' in weights, f"{dt.value} missing sentinel key"

    def test_enable_sentinel_config(self):
        cfg = self.Config(enable_sentinel=False)
        assert cfg.enable_sentinel is False
        cfg2 = self.Config()
        assert cfg2.enable_sentinel is True


class TestReadSentinelScore:
    """Test _read_sentinel_score method on UnifiedThreatEngine."""

    def _make_engine(self, tmp_path, enable_sentinel=True, deployment='fortress'):
        """Create a minimal UnifiedThreatEngine with mocked dependencies."""
        from core.qsecbit.unified_engine import UnifiedThreatEngine, UnifiedEngineConfig, DeploymentType

        dt = getattr(DeploymentType, deployment.upper())
        config = UnifiedEngineConfig(
            deployment_type=dt,
            enable_xdp=False,
            enable_energy_monitoring=False,
            enable_ml_classifier=False,
            enable_response_orchestration=False,
            enable_sentinel=enable_sentinel,
            data_dir=str(tmp_path),
        )
        # Patch detector classes to avoid hardware deps
        patches = {
            'L2DataLinkDetector': MagicMock(return_value=MagicMock()),
            'L3NetworkDetector': MagicMock(return_value=MagicMock()),
            'L4TransportDetector': MagicMock(return_value=MagicMock()),
            'L5SessionDetector': MagicMock(return_value=MagicMock()),
            'L7ApplicationDetector': MagicMock(return_value=MagicMock()),
        }
        with patch.multiple('core.qsecbit.unified_engine', **patches):
            engine = UnifiedThreatEngine(config)
        return engine

    def test_no_cache_file_returns_zero(self, tmp_path):
        engine = self._make_engine(tmp_path)
        score = engine._read_sentinel_score()
        assert score == 0.0

    def test_reads_max_malicious_score(self, tmp_path):
        import json
        cache = tmp_path / "sentinel_scores.json"
        cache.write_text(json.dumps({
            "cycle": 1, "scored": 3,
            "verdicts": {"malicious": 2, "benign": 1},
            "malicious_ips": [
                {"ip": "1.2.3.4", "score": 0.85, "confidence": 0.7},
                {"ip": "5.6.7.8", "score": 0.92, "confidence": 0.8},
            ],
            "suspicious_ips": [],
        }))
        engine = self._make_engine(tmp_path)
        score = engine._read_sentinel_score()
        assert abs(score - 0.92) < 1e-10

    def test_suspicious_score_included(self, tmp_path):
        import json
        cache = tmp_path / "sentinel_scores.json"
        cache.write_text(json.dumps({
            "cycle": 1, "scored": 2,
            "verdicts": {"suspicious": 1, "benign": 1},
            "malicious_ips": [],
            "suspicious_ips": [
                {"ip": "10.0.0.1", "score": 0.55, "confidence": 0.4},
            ],
        }))
        engine = self._make_engine(tmp_path)
        score = engine._read_sentinel_score()
        assert abs(score - 0.55) < 1e-10

    def test_sentinel_disabled_returns_zero(self, tmp_path):
        import json
        cache = tmp_path / "sentinel_scores.json"
        cache.write_text(json.dumps({
            "cycle": 1, "scored": 1,
            "malicious_ips": [{"ip": "1.2.3.4", "score": 0.9}],
            "suspicious_ips": [],
        }))
        engine = self._make_engine(tmp_path, enable_sentinel=False)
        score = engine._read_sentinel_score()
        assert score == 0.0

    def test_guardian_zero_weight_returns_zero(self, tmp_path):
        """Guardian has sentinel weight=0, so _read_sentinel_score short-circuits."""
        import json
        cache = tmp_path / "sentinel_scores.json"
        cache.write_text(json.dumps({
            "cycle": 1, "scored": 1,
            "malicious_ips": [{"ip": "1.2.3.4", "score": 0.9}],
            "suspicious_ips": [],
        }))
        engine = self._make_engine(tmp_path, deployment='guardian')
        score = engine._read_sentinel_score()
        assert score == 0.0

    def test_mtime_caching(self, tmp_path):
        """Same file mtime should return cached score without re-reading."""
        import json
        cache = tmp_path / "sentinel_scores.json"
        cache.write_text(json.dumps({
            "cycle": 1, "scored": 1,
            "malicious_ips": [{"ip": "1.2.3.4", "score": 0.75}],
            "suspicious_ips": [],
        }))
        engine = self._make_engine(tmp_path)
        s1 = engine._read_sentinel_score()
        assert abs(s1 - 0.75) < 1e-10

        # Second read without mtime change — should use cache
        s2 = engine._read_sentinel_score()
        assert abs(s2 - 0.75) < 1e-10


class TestModuleImportsPhase34:
    """Test that Phase 3+4 modules are importable."""

    def test_import_sentinel_lifecycle(self):
        import importlib
        mod = importlib.import_module('sentinel_lifecycle')
        assert hasattr(mod, 'PageHinkleyDetector')
        assert hasattr(mod, 'fishers_exact_one_sided')
        assert hasattr(mod, 'compute_metrics')
        assert hasattr(mod, 'SentinelLifecycle')

    def test_import_hydra_bridge(self):
        from core.aegis.bridges.hydra_bridge import HydraBridge
        assert hasattr(HydraBridge, 'poll')
        assert HydraBridge.name == "hydra"
        assert HydraBridge.poll_interval == 10.0

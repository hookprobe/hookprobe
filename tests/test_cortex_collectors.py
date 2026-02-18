"""
Tests for Cortex Live Data Collectors.

Validates that skeleton sleep-loops have been replaced with real data collection logic.
"""

import asyncio
import json
import os
import tempfile

import pytest

from shared.cortex.backend.data_collector import (
    HTPCollector,
    NeuroCollector,
    QsecbitCollector,
)


class TestHTPCollector:
    """Test HTP mesh event collection."""

    def test_collector_initializes(self):
        events = []
        collector = HTPCollector(on_event=events.append)
        assert collector.running is False

    def test_collector_reads_events_from_file(self):
        events = []
        collector = HTPCollector(on_event=events.append)

        # Create a mock mesh events file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({
                "events": [
                    {
                        "id": "ev-1",
                        "type": "attack_detected",
                        "source_lat": 51.5,
                        "source_lng": -0.1,
                        "source_label": "London",
                        "target_lat": 40.7,
                        "target_lng": -74.0,
                        "target_label": "NYC",
                        "node_id": "fortress-001",
                    }
                ]
            }, f)
            events_file = f.name

        try:
            os.environ["MESH_STATE_FILE"] = events_file
            result = collector._read_events()
            assert len(result) == 1
            assert result[0]["source_lat"] == 51.5

            # Process the event
            collector._handle_htp_event(result[0])
            assert len(events) == 1
            assert events[0]["type"] == "attack_detected"
            assert events[0]["source"]["lat"] == 51.5
        finally:
            os.environ.pop("MESH_STATE_FILE", None)
            os.unlink(events_file)

    def test_collector_deduplicates_events(self):
        collector = HTPCollector(on_event=lambda e: None)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({"events": [{"id": "ev-1"}, {"id": "ev-2"}]}, f)
            events_file = f.name

        try:
            os.environ["MESH_STATE_FILE"] = events_file
            # First read: 2 new events
            result1 = collector._read_events()
            assert len(result1) == 2
            # Second read: 0 new events (same file)
            result2 = collector._read_events()
            assert len(result2) == 0
        finally:
            os.environ.pop("MESH_STATE_FILE", None)
            os.unlink(events_file)

    def test_collector_handles_missing_file(self):
        collector = HTPCollector(on_event=lambda e: None)
        os.environ["MESH_STATE_FILE"] = "/nonexistent/mesh.json"
        try:
            result = collector._read_events()
            assert result == []
        finally:
            os.environ.pop("MESH_STATE_FILE", None)


class TestNeuroCollector:
    """Test Neuro TER event collection."""

    def test_collector_reads_ter_events(self):
        events = []
        collector = NeuroCollector(on_event=events.append)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({
                "events": [
                    {"sequence": 1, "node_id": "node-1", "resonance": 0.9, "drift": 0.01},
                    {"sequence": 2, "node_id": "node-1", "resonance": 0.4, "drift": 0.08},
                ]
            }, f)
            ter_file = f.name

        try:
            os.environ["NEURO_TER_FILE"] = ter_file
            result = collector._read_ter_events()
            assert len(result) == 2

            # Process events
            for ev in result:
                collector._handle_weight_event(ev)
            assert len(events) == 2
            assert events[0]["status"] == "synchronized"  # 0.9 > 0.8
            assert events[1]["status"] == "drifting"  # 0.4 < 0.5
        finally:
            os.environ.pop("NEURO_TER_FILE", None)
            os.unlink(ter_file)

    def test_collector_tracks_sequence(self):
        collector = NeuroCollector(on_event=lambda e: None)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({
                "events": [
                    {"sequence": 5, "node_id": "n", "resonance": 0.5},
                ]
            }, f)
            ter_file = f.name

        try:
            os.environ["NEURO_TER_FILE"] = ter_file
            result1 = collector._read_ter_events()
            assert len(result1) == 1
            assert collector._last_sequence == 5
            # Second read: same sequence, no new events
            result2 = collector._read_ter_events()
            assert len(result2) == 0
        finally:
            os.environ.pop("NEURO_TER_FILE", None)
            os.unlink(ter_file)


class TestQsecbitCollector:
    """Test QSecBit RAG status collection."""

    def test_collector_reads_stats(self):
        events = []
        collector = QsecbitCollector(on_event=events.append)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({
                "node_id": "fortress-001",
                "score": 0.72,
                "status": "GREEN",
                "layers": {"l2": 0.9, "l5": 0.6},
            }, f)
            stats_file = f.name

        try:
            # Monkey-patch the stats path
            import shared.cortex.backend.data_collector as dc
            old_path = dc.QSECBIT_STATS_PATH
            dc.QSECBIT_STATS_PATH = stats_file

            update = collector._read_qsecbit_stats()
            assert update is not None
            assert update["score"] == 0.72
            assert update["status"] == "green"

            collector._handle_score_update(update)
            assert len(events) == 1
            assert events[0]["color"] == "#00ff00"

            dc.QSECBIT_STATS_PATH = old_path
        finally:
            os.unlink(stats_file)

    def test_collector_skips_unchanged_score(self):
        collector = QsecbitCollector(on_event=lambda e: None)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({"score": 0.5, "status": "AMBER"}, f)
            stats_file = f.name

        try:
            import shared.cortex.backend.data_collector as dc
            old_path = dc.QSECBIT_STATS_PATH
            dc.QSECBIT_STATS_PATH = stats_file

            # First read: returns update
            update1 = collector._read_qsecbit_stats()
            assert update1 is not None
            # Second read: same data, returns None
            update2 = collector._read_qsecbit_stats()
            assert update2 is None

            dc.QSECBIT_STATS_PATH = old_path
        finally:
            os.unlink(stats_file)

    def test_collector_handles_missing_stats(self):
        collector = QsecbitCollector(on_event=lambda e: None)
        import shared.cortex.backend.data_collector as dc
        old_path = dc.QSECBIT_STATS_PATH
        dc.QSECBIT_STATS_PATH = "/nonexistent/stats.json"
        update = collector._read_qsecbit_stats()
        assert update is None
        dc.QSECBIT_STATS_PATH = old_path

    def test_rag_color_mapping(self):
        events = []
        collector = QsecbitCollector(on_event=events.append)
        collector._handle_score_update({
            "node_id": "test", "score": 0.2, "status": "red"
        })
        assert events[0]["color"] == "#ff0000"

#!/usr/bin/env python3
"""
ClickHouse Client for N8N Integration
Handles event storage and analytics queries
"""

import requests
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ClickHouseClient:
    """
    Client for ClickHouse database operations

    Usage:
        ch = ClickHouseClient(host="localhost", port=8123)
        ch.insert_event(event_data)
        results = ch.query("SELECT * FROM security_events LIMIT 10")
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8123,
        database: str = "hookprobe",
        user: str = "default",
        password: str = "",
        timeout: int = 30
    ):
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.timeout = timeout
        self.base_url = f"http://{host}:{port}"

    def _execute(self, query: str, data: Optional[str] = None) -> requests.Response:
        """Execute a ClickHouse query"""
        params = {
            "database": self.database,
            "user": self.user
        }

        if self.password:
            params["password"] = self.password

        try:
            if data:
                response = requests.post(
                    self.base_url,
                    params=params,
                    data=f"{query}\n{data}",
                    timeout=self.timeout
                )
            else:
                response = requests.post(
                    self.base_url,
                    params=params,
                    data=query,
                    timeout=self.timeout
                )

            response.raise_for_status()
            return response

        except requests.RequestException as e:
            logger.error(f"ClickHouse query error: {e}")
            raise

    def query(self, sql: str, format: str = "JSONEachRow") -> List[Dict[str, Any]]:
        """
        Execute a SELECT query

        Args:
            sql: SQL query
            format: Output format (JSONEachRow, JSON, CSV, etc.)

        Returns:
            List of result dictionaries
        """
        query = f"{sql} FORMAT {format}"
        response = self._execute(query)

        if format == "JSONEachRow":
            return [json.loads(line) for line in response.text.strip().split('\n') if line]
        elif format == "JSON":
            return json.loads(response.text).get('data', [])
        else:
            return response.text.split('\n')

    def insert_event(self, event: Dict[str, Any], table: str = "security_events") -> bool:
        """
        Insert a security event into ClickHouse

        Args:
            event: Event data dictionary
            table: Target table name

        Returns:
            True if successful
        """
        # Ensure required fields
        if 'timestamp' not in event:
            event['timestamp'] = datetime.utcnow().isoformat()

        query = f"INSERT INTO {table} FORMAT JSONEachRow"
        data = json.dumps(event)

        try:
            self._execute(query, data)
            logger.info(f"Inserted event into {table}")
            return True

        except Exception as e:
            logger.error(f"Failed to insert event: {e}")
            return False

    def insert_batch(self, events: List[Dict[str, Any]], table: str = "security_events") -> bool:
        """
        Insert multiple events in batch

        Args:
            events: List of event dictionaries
            table: Target table name

        Returns:
            True if successful
        """
        query = f"INSERT INTO {table} FORMAT JSONEachRow"
        data = '\n'.join([json.dumps(event) for event in events])

        try:
            self._execute(query, data)
            logger.info(f"Inserted {len(events)} events into {table}")
            return True

        except Exception as e:
            logger.error(f"Failed to insert batch: {e}")
            return False

    def get_top_threats(self, hours: int = 1, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get top threats in the last N hours

        Args:
            hours: Time window in hours
            limit: Number of results

        Returns:
            List of top threat sources
        """
        sql = f"""
        SELECT
            source_ip,
            COUNT(*) as event_count,
            AVG(qsecbit_score) as avg_score,
            MAX(qsecbit_score) as max_score,
            groupArray(event_type) as event_types
        FROM security_events
        WHERE timestamp >= now() - INTERVAL {hours} HOUR
            AND qsecbit_score >= 0.7
        GROUP BY source_ip
        ORDER BY max_score DESC, event_count DESC
        LIMIT {limit}
        """

        return self.query(sql)

    def get_response_effectiveness(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get automated response effectiveness metrics

        Args:
            hours: Time window in hours

        Returns:
            Response statistics
        """
        sql = f"""
        SELECT
            response_action,
            COUNT(*) as total_actions,
            AVG(response_duration_ms) as avg_duration_ms,
            SUM(CASE WHEN success = true THEN 1 ELSE 0 END) / COUNT(*) * 100 as success_rate
        FROM automated_responses
        WHERE timestamp >= now() - INTERVAL {hours} HOUR
        GROUP BY response_action
        """

        return self.query(sql)

    def get_threat_timeline(self, hours: int = 24, interval_minutes: int = 5) -> List[Dict[str, Any]]:
        """
        Get threat score timeline

        Args:
            hours: Time window in hours
            interval_minutes: Time bucket size in minutes

        Returns:
            Timeline data
        """
        sql = f"""
        SELECT
            toStartOfInterval(timestamp, INTERVAL {interval_minutes} MINUTE) as time_bucket,
            COUNT(*) as event_count,
            AVG(qsecbit_score) as avg_score,
            MAX(qsecbit_score) as max_score,
            COUNT(DISTINCT source_ip) as unique_sources
        FROM security_events
        WHERE timestamp >= now() - INTERVAL {hours} HOUR
        GROUP BY time_bucket
        ORDER BY time_bucket ASC
        """

        return self.query(sql)

    def create_tables(self) -> bool:
        """
        Create required database tables

        Returns:
            True if successful
        """
        # Read schema from file
        try:
            import os
            schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')

            with open(schema_path, 'r') as f:
                schema = f.read()

            # Execute each statement
            for statement in schema.split(';'):
                if statement.strip():
                    self._execute(statement)

            logger.info("Database tables created successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
            return False


# Example usage
if __name__ == "__main__":
    ch = ClickHouseClient()

    # Test event
    test_event = {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": "192.168.1.100",
        "destination_ip": "10.200.1.5",
        "event_type": "port_scan",
        "qsecbit_score": 0.85,
        "severity": "high",
        "tenant_id": "test"
    }

    # Insert event
    ch.insert_event(test_event)

    # Query top threats
    top_threats = ch.get_top_threats(hours=1)
    print(f"Top Threats: {json.dumps(top_threats, indent=2)}")

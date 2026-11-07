#!/usr/bin/env python3
"""
Validate N8N workflow JSON files
Checks structure, required fields, and connections
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any

class WorkflowValidator:
    """Validator for N8N workflow files"""

    REQUIRED_FIELDS = ['name', 'nodes', 'connections']
    REQUIRED_NODE_FIELDS = ['parameters', 'id', 'name', 'type', 'position']

    def __init__(self, workflows_dir: str):
        self.workflows_dir = Path(workflows_dir)
        self.errors = []
        self.warnings = []

    def validate_workflow_structure(self, workflow: Dict[str, Any], filename: str) -> bool:
        """Validate basic workflow structure"""
        valid = True

        # Check required top-level fields
        for field in self.REQUIRED_FIELDS:
            if field not in workflow:
                self.errors.append(f"{filename}: Missing required field '{field}'")
                valid = False

        # Check nodes
        if 'nodes' in workflow:
            if not isinstance(workflow['nodes'], list):
                self.errors.append(f"{filename}: 'nodes' must be a list")
                valid = False
            elif len(workflow['nodes']) == 0:
                self.warnings.append(f"{filename}: Workflow has no nodes")

        # Check connections
        if 'connections' in workflow:
            if not isinstance(workflow['connections'], dict):
                self.errors.append(f"{filename}: 'connections' must be a dictionary")
                valid = False

        return valid

    def validate_nodes(self, workflow: Dict[str, Any], filename: str) -> bool:
        """Validate node definitions"""
        valid = True
        node_ids = set()
        node_names = set()

        for idx, node in enumerate(workflow.get('nodes', [])):
            # Check required node fields
            for field in self.REQUIRED_NODE_FIELDS:
                if field not in node:
                    self.errors.append(
                        f"{filename}: Node {idx} missing required field '{field}'"
                    )
                    valid = False

            # Check for duplicate IDs
            node_id = node.get('id')
            if node_id in node_ids:
                self.errors.append(
                    f"{filename}: Duplicate node ID '{node_id}'"
                )
                valid = False
            node_ids.add(node_id)

            # Check for duplicate names
            node_name = node.get('name')
            if node_name in node_names:
                self.warnings.append(
                    f"{filename}: Duplicate node name '{node_name}'"
                )
            node_names.add(node_name)

            # Validate position
            position = node.get('position', [])
            if not isinstance(position, list) or len(position) != 2:
                self.errors.append(
                    f"{filename}: Node '{node_name}' has invalid position"
                )
                valid = False

        return valid

    def validate_connections(self, workflow: Dict[str, Any], filename: str) -> bool:
        """Validate node connections"""
        valid = True
        node_names = {node['name'] for node in workflow.get('nodes', [])}
        connections = workflow.get('connections', {})

        for source_node, targets in connections.items():
            # Check if source node exists
            if source_node not in node_names:
                self.errors.append(
                    f"{filename}: Connection references non-existent source node '{source_node}'"
                )
                valid = False
                continue

            # Validate target connections
            if not isinstance(targets, dict):
                self.errors.append(
                    f"{filename}: Connections for '{source_node}' must be a dictionary"
                )
                valid = False
                continue

            for connection_type, connection_list in targets.items():
                if not isinstance(connection_list, list):
                    self.errors.append(
                        f"{filename}: Connection list for '{source_node}.{connection_type}' must be a list"
                    )
                    valid = False
                    continue

                for connections_group in connection_list:
                    if not isinstance(connections_group, list):
                        continue

                    for connection in connections_group:
                        target_node = connection.get('node')
                        if target_node and target_node not in node_names:
                            self.errors.append(
                                f"{filename}: Connection references non-existent target node '{target_node}'"
                            )
                            valid = False

        return valid

    def validate_file(self, filepath: Path) -> bool:
        """Validate a single workflow file"""
        try:
            with open(filepath, 'r') as f:
                workflow = json.load(f)

            filename = filepath.name

            # Run all validations
            valid = all([
                self.validate_workflow_structure(workflow, filename),
                self.validate_nodes(workflow, filename),
                self.validate_connections(workflow, filename)
            ])

            return valid

        except json.JSONDecodeError as e:
            self.errors.append(f"{filepath.name}: Invalid JSON - {str(e)}")
            return False
        except Exception as e:
            self.errors.append(f"{filepath.name}: Unexpected error - {str(e)}")
            return False

    def validate_all(self) -> bool:
        """Validate all workflow files in the directory"""
        workflow_files = list(self.workflows_dir.rglob('*.json'))

        if not workflow_files:
            self.warnings.append(f"No workflow files found in {self.workflows_dir}")
            return True

        print(f"Validating {len(workflow_files)} workflow files...")

        all_valid = True
        for filepath in workflow_files:
            print(f"  Checking: {filepath.relative_to(self.workflows_dir)}...", end=' ')
            if self.validate_file(filepath):
                print("✓")
            else:
                print("✗")
                all_valid = False

        return all_valid

    def print_report(self):
        """Print validation report"""
        print("\n" + "="*60)
        print("VALIDATION REPORT")
        print("="*60)

        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)}):")
            for error in self.errors:
                print(f"  - {error}")

        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  - {warning}")

        if not self.errors and not self.warnings:
            print("\n✅ All workflows valid!")

        print("\n" + "="*60)


def main():
    """Main validation script"""
    # Get workflows directory
    script_dir = Path(__file__).parent
    workflows_dir = script_dir.parent / 'workflows'

    if not workflows_dir.exists():
        print(f"Error: Workflows directory not found: {workflows_dir}")
        return 1

    # Run validation
    validator = WorkflowValidator(str(workflows_dir))
    success = validator.validate_all()
    validator.print_report()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

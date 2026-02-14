"""
NAPSE Signature Converter

Converts Suricata rules to NAPSE YAML format for migration.

Usage:
    python -m core.napse.signatures.converter \
        --input shared/aiochi/containers/configs/suricata/rules/local.rules \
        --output core/napse/signatures/converted_rules.yaml

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import re
import sys
import yaml
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def parse_suricata_rule(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single Suricata rule into a dictionary.

    Format: action proto src_ip src_port -> dst_ip dst_port (options)
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # Match: alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"..."; ...)
    match = re.match(
        r'(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+\((.+)\)',
        line
    )
    if not match:
        return None

    action, proto, src_ip, src_port, dst_ip, dst_port, options_str = match.groups()

    # Parse options
    options = {}
    for opt_match in re.finditer(r'(\w+)\s*:\s*"?([^";]*)"?\s*;', options_str):
        key, value = opt_match.groups()
        options[key] = value.strip()

    return {
        'action': action,
        'proto': proto,
        'src_ip': src_ip,
        'src_port': src_port,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'options': options,
    }


def suricata_to_napse(rule: Dict[str, Any], base_id: int = 2000000) -> Dict[str, Any]:
    """Convert a parsed Suricata rule to NAPSE format."""
    opts = rule['options']
    sid = int(opts.get('sid', base_id))

    napse_rule: Dict[str, Any] = {
        'id': sid,
        'msg': opts.get('msg', 'Converted Suricata rule'),
        'category': opts.get('classtype', 'unknown'),
        'severity': 5 - min(int(opts.get('priority', 3)), 4),
        'layer': 7,
        'proto': rule['proto'],
    }

    # Convert dst_port
    if rule['dst_port'] not in ('any', '$HTTP_PORTS'):
        try:
            napse_rule['dst_port'] = int(rule['dst_port'])
        except ValueError:
            pass

    # Convert content patterns
    contents = []
    for key in ('content', 'pcre'):
        if key in opts:
            contents.append(opts[key])

    if contents:
        napse_rule['detection'] = {
            'type': 'pattern',
            'content': contents,
            'match_mode': 'any',
        }

    return napse_rule


def convert_file(input_path: str, output_path: str) -> int:
    """Convert a Suricata rules file to NAPSE YAML."""
    input_file = Path(input_path)
    if not input_file.exists():
        logger.error("Input file not found: %s", input_path)
        return 1

    rules = []
    with open(input_file) as f:
        for line in f:
            parsed = parse_suricata_rule(line)
            if parsed:
                napse_rule = suricata_to_napse(parsed)
                rules.append(napse_rule)

    output = {
        'version': '1.0.0',
        'source': f'Converted from {input_path}',
        'rules': rules,
    }

    with open(output_path, 'w') as f:
        yaml.dump(output, f, default_flow_style=False, sort_keys=False)

    logger.info("Converted %d rules from %s to %s", len(rules), input_path, output_path)
    return 0


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Convert Suricata rules to NAPSE format')
    parser.add_argument('--input', required=True, help='Suricata rules file')
    parser.add_argument('--output', required=True, help='NAPSE YAML output')
    args = parser.parse_args()
    sys.exit(convert_file(args.input, args.output))

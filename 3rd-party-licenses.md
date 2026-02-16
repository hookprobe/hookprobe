# Third-Party Licenses

This document lists all third-party components used by HookProbe v5.0 and their respective licenses.

**License Summary**: All components use permissive licenses compatible with commercial use. HookProbe is 100% GPL-free.

---

## 📋 License Categories

### ✅ Fully Permissive (No Restrictions)
- MIT License
- BSD-2-Clause, BSD-3-Clause
- Apache License 2.0
- PostgreSQL License

### ⚠️ Copyleft (Service Use OK)
- AGPL-3.0 (Grafana) - Running as a service is permitted

### 🔧 System Tools (No Linking)
- GPL-2 (nftables, kernel modules) - System utilities, not linked to HookProbe code

---

## 🏗️ Infrastructure Components

### Container Runtime

**Podman**
- **Version**: 4.9+
- **License**: Apache License 2.0
- **Source**: https://podman.io/
- **Usage**: Container management
- **Commercial Use**: ✅ Yes

**Buildah**
- **Version**: 1.35+
- **License**: Apache License 2.0
- **Source**: https://buildah.io/
- **Usage**: Container image building
- **Commercial Use**: ✅ Yes

**Skopeo**
- **Version**: 1.14+
- **License**: Apache License 2.0
- **Source**: https://github.com/containers/skopeo
- **Usage**: Container image operations
- **Commercial Use**: ✅ Yes

---

### Networking

**Open vSwitch (OVS)**
- **Version**: 3.x
- **License**: Apache License 2.0
- **Source**: https://www.openvswitch.org/
- **Usage**: Virtual networking, VXLAN tunnels
- **Commercial Use**: ✅ Yes

**IPsec (strongSwan)**
- **Version**: Latest
- **License**: GPL-2 (system utility)
- **Source**: https://www.strongswan.org/
- **Usage**: VXLAN encryption (optional)
- **Note**: System utility, not linked to HookProbe code
- **Commercial Use**: ✅ Yes (as system utility)

**nftables**
- **Version**: Latest
- **License**: GPL-2 (kernel/system tool)
- **Source**: https://netfilter.org/
- **Usage**: Firewall management
- **Note**: System utility, not linked to HookProbe code
- **Commercial Use**: ✅ Yes (as system utility)

---

## 🌐 Web Application Stack

### Web Server

**Nginx**
- **Version**: 1.27+
- **License**: BSD-2-Clause
- **Source**: https://nginx.org/
- **Usage**: Reverse proxy, static file serving
- **Commercial Use**: ✅ Yes

### Application Framework

**Django**
- **Version**: 5.0.6
- **License**: BSD-3-Clause
- **Source**: https://www.djangoproject.com/
- **Usage**: Web framework
- **Commercial Use**: ✅ Yes

**Gunicorn**
- **Version**: 22.0+
- **License**: MIT License
- **Source**: https://gunicorn.org/
- **Usage**: WSGI HTTP server
- **Commercial Use**: ✅ Yes

**Django REST Framework**
- **Version**: 3.15+
- **License**: BSD-3-Clause
- **Source**: https://www.django-rest-framework.org/
- **Usage**: REST API
- **Commercial Use**: ✅ Yes

---

### Database

**PostgreSQL**
- **Version**: 16+
- **License**: PostgreSQL License (similar to BSD/MIT)
- **Source**: https://www.postgresql.org/
- **Usage**: Relational database
- **Commercial Use**: ✅ Yes
- **License Text**: https://www.postgresql.org/about/licence/

**psycopg2**
- **Version**: 2.9+
- **License**: LGPL-3.0 (with runtime linking exception)
- **Source**: https://www.psycopg.org/
- **Usage**: PostgreSQL adapter for Python
- **Note**: Runtime linking is allowed
- **Commercial Use**: ✅ Yes

---

### Cache

**Redis**
- **Version**: 7.x
- **License**: BSD-3-Clause (until v7.4)
- **Source**: https://redis.io/
- **Usage**: In-memory cache
- **Commercial Use**: ✅ Yes

**Valkey**
- **Version**: 8.0+ (Redis fork)
- **License**: BSD-3-Clause
- **Source**: https://valkey.io/
- **Usage**: Alternative cache (optional)
- **Commercial Use**: ✅ Yes

---

## 🛡️ Security Components

### Web Application Firewall

**ModSecurity**
- **Version**: 3.x
- **License**: Apache License 2.0
- **Source**: https://github.com/SpiderLabs/ModSecurity
- **Usage**: Web application firewall
- **Commercial Use**: ✅ Yes

**OWASP ModSecurity Core Rule Set (CRS)**
- **Version**: 4.x
- **License**: Apache License 2.0
- **Source**: https://coreruleset.org/
- **Usage**: WAF rules
- **Commercial Use**: ✅ Yes

---

### Network Security Engines

**Zig (Aegis build toolchain)**
- **Version**: 0.14+
- **License**: MIT License
- **Source**: https://ziglang.org/
- **Usage**: Aegis eBPF/XDP packet capture engine
- **Commercial Use**: ✅ Yes

**Mojo (Napse runtime)**
- **Version**: 25.1+
- **License**: Modular Community License
- **Source**: https://www.modular.com/mojo
- **Usage**: Napse AI intent attribution engine
- **Note**: Free for commercial use
- **Commercial Use**: ✅ Yes

---

## 🔐 Identity & Access Management

**Keycloak**
- **Version**: 26.0+
- **License**: Apache License 2.0
- **Source**: https://www.keycloak.org/
- **Usage**: SSO, identity management
- **Commercial Use**: ✅ Yes

---

## 📊 Observability & Monitoring

### Metrics & Logs

**VictoriaMetrics**
- **Version**: Latest
- **License**: Apache License 2.0
- **Source**: https://victoriametrics.com/
- **Usage**: Time-series database for metrics
- **Commercial Use**: ✅ Yes

**ClickHouse**
- **Version**: 24.11+
- **License**: Apache License 2.0
- **Source**: https://clickhouse.com/
- **Usage**: OLAP database for edge security analytics (local deployment)
- **Commercial Use**: ✅ Yes

**Vector**
- **Version**: Latest
- **License**: MPL-2.0 (Mozilla Public License 2.0)
- **Source**: https://vector.dev/
- **Usage**: Log collection and forwarding
- **Note**: MPL-2.0 is file-level copyleft (permissive for service use)
- **Commercial Use**: ✅ Yes

---

### Dashboards

**Grafana**
- **Version**: 11.4+
- **License**: AGPL-3.0
- **Source**: https://grafana.com/
- **Usage**: Visualization and dashboards
- **Note**: AGPL allows running as a service without source disclosure
- **Commercial Use**: ✅ Yes (as hosted service)
- **Reference**: https://grafana.com/licensing/

---

### Exporters

**Prometheus Node Exporter**
- **Version**: Latest
- **License**: Apache License 2.0
- **Source**: https://github.com/prometheus/node_exporter
- **Usage**: Host metrics collection
- **Commercial Use**: ✅ Yes

**cAdvisor**
- **Version**: Latest
- **License**: Apache License 2.0
- **Source**: https://github.com/google/cadvisor
- **Usage**: Container metrics (optional)
- **Commercial Use**: ✅ Yes

---

## 🤖 AI/ML Components

### Qsecbit

**Qsecbit Core**
- **Version**: 1.0
- **License**: MIT License
- **Author**: Andrei Toma, HookProbe Team
- **Source**: Included in this repository
- **Usage**: Threat analysis algorithm
- **Commercial Use**: ✅ Yes

---

### Python Libraries

**NumPy**
- **Version**: 1.26+
- **License**: BSD-3-Clause
- **Source**: https://numpy.org/
- **Usage**: Scientific computing
- **Commercial Use**: ✅ Yes

**SciPy**
- **Version**: 1.11+
- **License**: BSD-3-Clause
- **Source**: https://scipy.org/
- **Usage**: Advanced algorithms (Mahalanobis distance, entropy)
- **Commercial Use**: ✅ Yes

**Flask**
- **Version**: 3.0+
- **License**: BSD-3-Clause
- **Source**: https://flask.palletsprojects.com/
- **Usage**: Qsecbit API server
- **Commercial Use**: ✅ Yes

---

## ☁️ Optional Components

**Cloudflare Tunnel (cloudflared)**
- **Version**: Latest
- **License**: Apache License 2.0
- **Source**: https://github.com/cloudflare/cloudflared
- **Usage**: Secure tunnel to Cloudflare network (optional)
- **Commercial Use**: ✅ Yes

---

## 🐍 Python Dependencies

All Python packages use permissive licenses:

| Package | Version | License |
|---------|---------|---------|
| Django | 5.0.6 | BSD-3-Clause |
| gunicorn | 22.0.0 | MIT |
| psycopg2-binary | 2.9.9 | LGPL-3 (linking allowed) |
| redis | 5.0.4 | MIT |
| celery | 5.4.0 | BSD-3-Clause |
| django-environ | 0.11.2 | MIT |
| Pillow | 10.3.0 | HPND (permissive) |
| djangorestframework | 3.15.1 | BSD-3-Clause |
| requests | 2.32.3 | Apache 2.0 |
| PyJWT | 2.8.0 | MIT |
| cryptography | 42.0.7 | Apache 2.0 / BSD |
| numpy | 1.26+ | BSD-3-Clause |
| scipy | 1.11+ | BSD-3-Clause |
| flask | 3.0+ | BSD-3-Clause |
| clickhouse-driver | 0.2.6+ | MIT |
| pymysql | 1.1.0+ | MIT |

---

## 📄 Full License Texts

### MIT License

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

### BSD-3-Clause License

```
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES ARE
DISCLAIMED.
```

### Apache License 2.0

```
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## ✅ GPL-Free Compliance Summary

### No GPL Components in Core

HookProbe's core software (scripts, Qsecbit, configurations) contains **zero GPL code**.

### System Utilities Exception

Some GPL tools are used as **system utilities** (nftables, kernel modules):
- Not linked to HookProbe code
- Standard Linux system components
- Used via command-line interface
- No license contamination

### Service Use Exception

Components with copyleft licenses are used as **services**:
- **Grafana (AGPL-3)**: Running as web service (allowed by AGPL)

### Commercial Use Clearance

✅ **All components are cleared for commercial use**

This includes:
- Selling HookProbe as a product
- Offering HookProbe as a service (SaaS)
- Using HookProbe in proprietary systems
- Embedding HookProbe in commercial appliances

**No source code disclosure required** for HookProbe deployments.

---

## 🔍 License Verification

### Automated Scanning

We use automated tools to verify licenses:

```bash
# Python dependencies
pip-licenses --format=markdown

# Container images
trivy image --scanners license hookprobe-django:v5

# npm packages (if any)
npx license-checker --summary
```

### Manual Review

All third-party components undergo manual license review:
1. License identified from official source
2. Terms analyzed for GPL compatibility
3. Commercial use clearance confirmed
4. Documentation updated

---

## 📞 License Questions

If you have questions about licensing:

**Email**: qsecbit@hookprobe.com

**Subject**: "Licensing Question - [Component Name]"

We'll respond within 48 hours.

---

## 🔄 Updates

This document is updated with each release to reflect:
- New third-party components
- Version updates
- License changes
- Clarifications

**Last Updated**: 2025-01-01  
**Document Version**: 1.0  
**HookProbe Version**: 5.0.0

---

## 🙏 Acknowledgments

We thank all the open-source projects and their maintainers for making HookProbe possible:

- The Grafana Labs team (VictoriaMetrics, Grafana)
- The ClickHouse team (Yandex/ClickHouse, Inc.)
- The Zig Software Foundation
- The Modular team (Mojo)
- The OWASP ModSecurity team
- The PostgreSQL Global Development Group
- The Django Software Foundation
- The Redis contributors
- All individual package maintainers

Their dedication to open source enables projects like HookProbe to exist.

---

**HookProbe - 100% GPL-Free, 100% Production-Ready**

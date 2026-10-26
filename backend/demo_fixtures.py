"""
Clearly labeled synthetic demo and benchmark fixtures ([SYNTHETIC DEMO FIXTURE]).
Designed to test multi-document entity resolution, multi-hop graph traversal, temporal markers,
contradiction detection, and global community summarization without fabricating real-world claims.
"""
from __future__ import annotations

from typing import Dict, List

SYNTHETIC_DEMO_DOCUMENTS: List[Dict[str, str]] = [
    {
        "filename": "01_infra_incident_report_2026.md",
        "mime_type": "text/markdown",
        "content": """# [SYNTHETIC DEMO FIXTURE] Infrastructure Post-Mortem: Incident INC-2026-041

[Page 1]
## 1. Executive Incident Overview
On October 14, 2026, Aurelia Financial Cloud experienced a severe transaction processing disruption logged as Incident INC-2026-041. Aurelia Financial Cloud operates Helios Payment Gateway (HPG), which processes real-time cross-border settlements in the Frankfurt Data Center. During Q4 2026, Helios Payment Gateway suffered a 14.5% error rate and recorded an MTTR of 95 minutes.

[Page 2]
## 2. Root Cause & Dependency Chain
Root cause analysis determined that Incident INC-2026-041 was caused by a memory leak in Chronos Consensus Engine v2.4. Helios Payment Gateway depends on Chronos Consensus Engine v2.4 for distributed ledger state synchronization. Furthermore, Chronos Consensus Engine v2.4 is hosted in the Frankfurt Data Center and depends on Hyperion Fiber Grid for low-latency inter-zone replication.

Earlier in Q3 2026, Chronos Consensus Engine v1.9 had operated without incident in the Tokyo Region, demonstrating that the regression is specific to Chronos Consensus Engine v2.4. Lead Architect Elena Vance authored the emergency patch that upgraded the cluster to Chronos Consensus Engine v2.5 on October 15, 2026.
""",
    },
    {
        "filename": "02_vendor_supply_chain_and_slas.md",
        "mime_type": "text/markdown",
        "content": """# [SYNTHETIC DEMO FIXTURE] Vendor Supply Chain & Telecom SLA Dossier

[Page 1]
## 1. Core Software & Telecom Suppliers
Chronos Consensus Engine v2.4 was developed by Vektor Distributed Labs. In Q2 2026, Vektor Distributed Labs was acquired by Omnibus Enterprise Holdings. Meanwhile, Hyperion Fiber Grid is operated by Stratos Telecom Group in the European Union.

[Page 2]
## 2. Service Level Agreement & Contradictory Uptime Reports
Aurelia Financial Cloud partnered with Stratos Telecom Group to guarantee redundant optical transport for the Frankfurt Data Center. In internal vendor telemetry for Q4 2026, Helios Payment Gateway reported 99.98% uptime SLA compliance. However, independent audit logs recorded that Helios Payment Gateway reported 98.40% uptime SLA compliance during Q4 2026 due to Incident INC-2026-041.

Additionally, Apex Settlement Vault US operates in the Northern Virginia Hub, whereas Apex Settlement Vault UK operates in the London Metro Zone. These two regional vaults remain physically isolated from the Frankfurt Data Center.
""",
    },
    {
        "filename": "03_regulatory_compliance_audit.md",
        "mime_type": "text/markdown",
        "content": """# [SYNTHETIC DEMO FIXTURE] European Regulatory & Resilience Audit AUD-2026-09

[Page 1]
## 1. DORA Compliance & Regulatory Scope
Aurelia Financial Cloud is regulated by DORA Article 19 and ISO/IEC 27001 for all critical payment systems in the European Union. Under DORA Article 19, any outage affecting Helios Payment Gateway impacts Meridian Retail Bank, which depends on Helios Payment Gateway for instant SEPA clearing.

[Page 2]
## 2. Downstream Impact & Financial Penalties
Because Incident INC-2026-041 disrupted Helios Payment Gateway on October 14, 2026, Meridian Retail Bank suffered a $4.2 million USD penalty and reported an RTO of 110 minutes during Audit AUD-2026-09. Chief Risk Officer Marcus Sterling certified the remediation report submitted under DORA Article 19.
""",
    },
]

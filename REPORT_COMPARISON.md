## COMPARISON: Event Mill PCAP Analysis vs. Dragos CADR3 Report

### DOCUMENT OVERVIEW
| Aspect | Event Mill PCAP | Dragos CADR3 |
|--------|-----------------|-------------|
| **Type** | Incident Analysis (Network Forensics) | Cybersecurity Architecture Design Review |
| **Focus** | Live PCAP capture analysis | Network design/configuration assessment |
| **Pages** | 7 pages | 28 pages |
| **Timeframe** | 4-hour capture (Apr 23, 2026) | Architectural review (ongoing) |
| **Methodology** | AI-driven behavioral analysis | Dragos methodology (asset mapping, threat modeling) |

---

### FINDINGS COMPARISON

#### ✓ SAME/ALIGNED FINDINGS

**1. SMB/RPC Protocol Risks**
- **Event Mill:** "Widespread IT protocol scanning (WinRM, SSH, RPC, SMB) from iDMZ servers into Process Control Network"
- **Dragos:** "SMBV1 Protocol Detected" (architectural finding)
- **Status:** ✓ Both identify SMB as a risk vector, though from different angles (tactical vs. architectural)

**2. Network Segmentation Issues**
- **Event Mill:** "Breakdown of segmentation between iDMZ (Level 3.5) and Process Control Network (Level 3)"
- **Dragos:** "ICS/OT Networks Utilizing VLAN 1" + "External Network Connections" analysis
- **Status:** ✓ Both identify segmentation failure, though Dragos focuses on VLAN design, Event Mill on actual traffic

**3. Authentication/Credential Exposure**
- **Event Mill:** "Cleartext SNMP community strings exposed"
- **Dragos:** "Weak Cisco authentication ciphers"
- **Status:** ✓ Similar theme: cleartext/weak auth is a vulnerability vector

#### ✗ DIFFERENT/UNIQUE FINDINGS

**Event Mill IDENTIFIED (Dragos did NOT):**
1. **Modbus WRITE commands from 10.188.64.31** - CRITICAL
   - Unauthorized Modbus FC5/FC16 writes to field devices
   - Direct manipulation threat
   - *Dragos didn't capture this in the design review*

2. **NetBus RAT port scanning (port 12345)** - CRITICAL
   - Server scanning for remote access trojan
   - Smoking gun indicator of compromise
   - *Dragos design review doesn't detect actual compromise indicators*

3. **Un-inventoried scanning device (10.75.30.122)** - HIGH
   - Performing SSH/SNMP reconnaissance
   - Asset not in known inventory
   - *Dragos has asset mapping but may not flag unknowns in real-time*

4. **Physical safety impact assessment** - MEDIUM
   - Explicit analysis of Modbus writes' impact on equipment (valves, motors, setpoints)
   - Safety-centric conclusion
   - *Dragos focused on architecture, not live attack implications*

**Dragos IDENTIFIED (Event Mill may NOT have in report):**
1. **Network topology and zone design issues** 
   - VLAN configuration problems
   - Architectural level concerns
   - *Event Mill's scope was incident analysis, not design review*

2. **Threat groups of interest** (BAUXITE, VOLTZITE, ELECTRUM, SYLVANITE since 2023)
   - Contextual threat intelligence
   - *Event Mill focused on the specific incident, not broader threat landscape*

3. **Cisco device hardening recommendations**
   - Device-specific cryptographic weaknesses
   - *Outside scope of PCAP-based analysis*

---

### KEY INSIGHT: COMPLEMENTARY TOOLS

**Dragos = Architectural Foundation (Preventive)**
- How the network *should* be designed
- Configuration weaknesses
- Recurring architectural flaws

**Event Mill = Tactical Detection (Detective)**
- What's *actually happening* in traffic
- Compromise indicators
- Real-time attack chains

**The Problem:** Dragos found the house had weak locks (SMB, VLAN 1, weak ciphers). Event Mill found someone *already inside* (compromised server, Modbus writes, RAT scanning).

---

### SEVERITY ALIGNMENT

| Finding | Event Mill | Dragos | Aligned? |
|---------|-----------|--------|----------|
| SMB/RPC exposure | HIGH (active scanning) | Medium (config issue) | ✓ Aligned |
| Segmentation failure | CRITICAL | High (design flaw) | ✓ Aligned |
| Credential exposure | MEDIUM (SNMP) | Medium (weak ciphers) | ✓ Aligned |
| **Modbus writes** | **CRITICAL** | *N/A (not detected)* | ✗ Different scope |
| **Live compromise** | **CRITICAL** | *N/A (design review)* | ✗ Different scope |

---

### BOTTOM LINE

**Who found what:**
- **Event Mill:** Found the *active attack in progress* (compromised server, Modbus writes, RAT scanning)
- **Dragos:** Found the *architectural vulnerabilities* that enabled the attack (bad segmentation, weak protocols)

**Neither contradicts the other.** Dragos identified the *blueprint flaws*, Event Mill found the *exploitation of those flaws in real-time*.

The fact that both identify segmentation and SMB/RPC issues validates the threat model. The fact that Event Mill found a compromise that Dragos wouldn't catch (in a design review) shows why both tools are needed: Dragos prevents, Event Mill detects.

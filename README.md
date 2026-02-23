# Home Lab: Network Traffic Monitoring and Threat Detection

**Author:** Le Randy Tran  
**Environment:** VirtualBox, Kali Linux  
**Tools Used:** Wireshark, Nmap, iptables  
**Status:** Completed

---

## Objective

Build a controlled virtual network environment to monitor live traffic, detect anomalous activity, and document findings using industry-standard tools. This lab simulates a basic SOC analyst workflow: observe, detect, investigate, report.

---

## Lab Environment

| Component | Details |
|---|---|
| Host OS | Windows 10/11 |
| Hypervisor | VirtualBox |
| Attacker/Monitor VM | Kali Linux |
| Target VM | Ubuntu Server 22.04 (Internal Network) |
| Network Mode | VirtualBox Internal Network + Host-Only Adapter |

### Network Diagram

```
[Host Machine]
      |
      | Host-Only Adapter (192.168.56.0/24)
      |
 _____|_______________________________
|                                     |
[Kali Linux VM]               [Ubuntu Server VM]
192.168.56.101                192.168.56.102
(Monitor / Attacker)          (Target)
```

---

## Setup Steps

### Step 1: Configure VirtualBox Network

1. Open VirtualBox and go to File > Host Network Manager
2. Create a Host-Only network: `192.168.56.0/24`
3. Assign both VMs to the Host-Only adapter
4. Set Kali Linux as the monitoring machine

### Step 2: Verify Connectivity

On Kali Linux, confirm both machines are on the same subnet:

```bash
ip a
ping 192.168.56.102
```

Expected output: ICMP replies from the Ubuntu target VM.

### Step 3: Start Wireshark Capture

Launch Wireshark on Kali Linux and begin capturing on the active interface (`eth0` or `enp0s3`):

```bash
sudo wireshark
```

Set a capture filter to isolate traffic between the two VMs:

```
host 192.168.56.102
```

---

## Phase 1: Baseline Traffic Capture

### Goal
Establish normal traffic patterns before introducing any scanning activity.

### Actions Taken
- Captured 2 minutes of idle traffic between VMs
- Observed ARP requests and ICMP echo packets
- Saved baseline capture as `baseline_capture.pcap`

### Findings
- ARP broadcasts from 192.168.56.101 to resolve 192.168.56.102
- No unexpected outbound connections
- DHCP lease confirmed on both machines

---

## Phase 2: Network Reconnaissance with Nmap

### Goal
Simulate an internal scan and observe how it appears in Wireshark.

### Command Used

```bash
sudo nmap -sV -O 192.168.56.102
```

Flag breakdown:
- `-sV`: Detect service versions running on open ports
- `-O`: Attempt OS fingerprinting

### Nmap Output (Sample)

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1
80/tcp   open  http    Apache httpd 2.4.52
3306/tcp closed mysql

OS: Linux 5.x
```

### Wireshark Observations During Scan

- High volume of SYN packets sent from 192.168.56.101 across multiple ports
- SYN-ACK responses on ports 22 and 80 confirmed open services
- TCP RST packets on closed ports (3306, 8080, etc.)
- Scan completed in under 30 seconds, generating 1,200+ packets

**Detection indicator:** A burst of SYN packets to sequential port numbers from a single source IP is a clear signature of a port scan.

---

## Phase 3: Wireshark Analysis and Filtering

### Filters Applied

| Filter | Purpose |
|---|---|
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Isolate SYN-only packets (scan detection) |
| `ip.src == 192.168.56.101` | Filter traffic from the scanning machine |
| `tcp.port == 22` | Isolate SSH traffic |
| `http` | Show all HTTP traffic |

### Key Findings

1. **Port scan detected:** 1,187 SYN packets sent in 28 seconds from single source. This pattern matches a classic TCP connect scan.
2. **Service enumeration confirmed:** Nmap successfully identified OpenSSH 8.9 and Apache 2.4.52 via banner grabbing.
3. **No encryption on port 80:** HTTP traffic captured in plaintext. Credentials or session tokens transmitted over this port are fully visible.

---

## Phase 4: Basic Firewall Rule with iptables

### Goal
Respond to the detected scan by blocking the source IP using iptables on the Ubuntu target.

### Command Executed on Ubuntu VM

```bash
sudo iptables -A INPUT -s 192.168.56.101 -j DROP
```

### Verification

Re-ran Nmap from Kali Linux after applying the rule:

```bash
sudo nmap -sV 192.168.56.102
```

Result: All ports returned as `filtered`. No SYN-ACK responses received. Rule confirmed working.

Saved the iptables rule persistently:

```bash
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

---

## Artifacts

| File | Description |
|---|---|
| `baseline_capture.pcap` | Pre-scan idle traffic |
| `scan_capture.pcap` | Traffic during Nmap scan |
| `nmap_output.txt` | Full Nmap results |
| `iptables_rules.txt` | Firewall rules applied |

---

## Lessons Learned

1. **Nmap scans are loud.** A basic SYN scan generates thousands of packets in seconds. Any SIEM with network visibility flags this immediately.
2. **Unencrypted services are a liability.** Port 80 HTTP traffic exposed full request and response data in Wireshark without any additional effort.
3. **iptables is effective but static.** Blocking a single IP works in a lab. In production, dynamic firewall rules (via a SIEM or SOAR) are required to scale this response.
4. **Baselining matters.** Without a baseline capture, distinguishing normal from abnormal traffic is guesswork.

---

## Skills Demonstrated

- Virtual network configuration and segmentation
- Passive traffic capture and protocol analysis with Wireshark
- Active network reconnaissance with Nmap
- Packet-level threat detection using capture filters
- Host-based firewall response with iptables
- Technical documentation of findings

---

## Tools and References

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [iptables Man Page](https://linux.die.net/man/8/iptables)
- CompTIA Security+ SY0-701 Study Material

---

## Next Steps

- Add a second target VM to simulate lateral movement detection
- Deploy Snort or Suricata as an IDS to automate scan detection
- Export Wireshark captures to Splunk for SIEM analysis practice

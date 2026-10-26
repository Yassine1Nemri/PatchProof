# PatchProof — Asset Inventory

## 1. Purpose

This inventory identifies the assets included in the PatchProof
vulnerability management lab. It establishes the initial asset
scope before vulnerability scanning and remediation.

## 2. Lab Environment

The lab contains five identified machines on the
172.16.220.0/24 network.

| Asset | IP Address | Operating System | Function | Criticality |
|---|---|---|---|---|
| DC01 | 172.16.220.10 | Windows Server 2022 Standard Evaluation | Active Directory, DNS, DHCP | Critical |
| WIN-CL | 172.16.220.11 | Windows 10 Education 22H2 | Domain workstation | Medium |
| WEB01 | 172.16.220.137 | Ubuntu Server | Web server | High |
| KALI-SCAN | 172.16.220.135 | Kali Linux | Vulnerability scanning | N/A |
| MS2 | 172.16.220.100 | Metasploitable 2 | Intentionally vulnerable legacy target | Low* |

*MS2's criticality rating is provisional. Its technical risk and
potential pivot risk will be evaluated during vulnerability assessment.

## 3. Verified Configuration

### DC01
- Windows Server 2022 Standard Evaluation.
- Active Directory Domain Services installed and running.
- DNS Server installed and running.
- DHCP Server installed and running.
- DHCP IPv4 scope: 172.16.220.100–172.16.220.200.
- WSUS is available but not installed.

### WIN-CL
- Windows 10 Education, version 22H2.
- OS build 19045.
- Joined to the lab domain.

### MS2
- Hostname: metasploitable.
- Operating system: Metasploitable 2.
- Primary interface: eth0.
- Primary IP: 172.16.220.100/24.
- SSH access verified using the msfadmin account.
- Secondary interface eth1 is currently down and has no IP address.
- The machine is intentionally vulnerable and must remain within
  the authorized lab environment.

### WEB01 and KALI-SCAN
- WEB01: 172.16.220.137.
- KALI-SCAN: 172.16.220.135.
- Further service and configuration discovery will be documented
  during scanning preparation.

## 4. Initial Risks and Follow-up Actions

1. Verify whether MS2's IP address conflicts with an active DHCP lease.
2. Confirm that MS2 is not bridged to an untrusted network.
3. Record the services and operating-system details discovered
   during baseline scanning.
4. Assess Windows 10 22H2 support status and applicable updates.
5. Establish baseline vulnerability scans before remediation.

## 5. Assessment Status

This inventory is the initial asset baseline. It does not represent
a completed vulnerability assessment. Findings, severity, remediation,
and verification results will be recorded in subsequent project phases.

## 6. DHCP Address Verification

The DHCP lease for 172.16.220.100 was checked on DC01.

- DHCP scope: 172.16.220.0/24
- Leased IP: 172.16.220.100
- Client MAC: 00:0c:29:fa:dd:2a
- Lease state: Active
- Lease expiration: 2026-10-28 09:07:51 (server-reported time)

The DHCP client MAC matches the MAC address of MS2's eth0 interface.
This supports identifying the lease as belonging to MS2. No conflict
is indicated by this lease, although this check alone does not rule
out every possible duplicate-IP condition.

Follow-up: consider creating a DHCP reservation for MS2.

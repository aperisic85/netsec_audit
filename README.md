# netsec-audit

Offline, rule-driven security auditor for network device configurations. Point it at a Cisco IOS config and it flags insecure settings — telnet, default SNMP communities, missing password encryption, exposed HTTP server, and more — mapped to CIS Benchmark references.

No cloud. No telemetry. One static binary. Rules live in a plain TOML file you can edit and extend without recompiling.

## Why

Reviewing device configs by hand doesn't scale past a handful of routers. `netsec-audit` encodes the checks you'd run manually into a fast, repeatable tool that fits into CI/CD and emits SARIF for GitHub code scanning.

## Install

```bash
cargo install --path .
# or build a release binary
cargo build --release   # target/release/netsec-audit
```

## Usage

```bash
# Audit a config against the bundled Cisco IOS rules
netsec-audit --config router.cfg

# Machine-readable output
netsec-audit --config router.cfg --format json
netsec-audit --config router.cfg --format sarif > results.sarif

# Fail CI if anything HIGH or above is found (default)
netsec-audit --config router.cfg --fail-on high

# Use a custom rule set
netsec-audit --config router.cfg --rules my-rules.toml
```

Exit codes: `0` clean (below threshold), `1` findings at/above `--fail-on`, `2` runtime error.

## Example output

```
netsec-audit  target: examples/vulnerable-router.cfg
14 rules evaluated, 14 findings

[CRITICAL] Default SNMP community string 'private' (cisco-ios-snmp-private)
    line 13
    > snmp-server community private RW
    The 'private' community typically grants SNMP write access, enabling remote reconfiguration.
    fix: Remove default communities; use SNMPv3 and restrict with ACLs.
    CIS Cisco IOS 3.x

[HIGH] Telnet enabled on VTY lines (cisco-ios-telnet-enabled)
    line 19
    > transport input telnet ssh
    Telnet transmits credentials and session data in cleartext, allowing trivial interception.
    fix: Use 'transport input ssh' on all VTY lines and disable telnet.
    CIS Cisco IOS 1.5.x

...

Summary: 1 critical, 3 high, 14 total
```

## Writing rules

Rules are TOML. Two matching modes:

```toml
[[rule]]
id = "cisco-ios-telnet-enabled"
title = "Telnet enabled on VTY lines"
severity = "high"                       # info | low | medium | high | critical
match = "present_regex"                 # finding when pattern IS found
pattern = 'transport input.*telnet'
description = "Telnet transmits credentials in cleartext."
remediation = "Use 'transport input ssh'."
cis = "CIS Cisco IOS 1.5.x"             # optional

[[rule]]
id = "cisco-ios-no-password-encryption"
title = "Password encryption service disabled"
severity = "medium"
match = "absent_regex"                   # finding when pattern is NOT found
pattern = 'service password-encryption'
description = "Type-7 passwords stored in plaintext."
remediation = "Add 'service password-encryption'."
```

`present_regex` reports one finding per matching line. `absent_regex` reports one config-wide finding when the pattern is missing.

## Roadmap

- More Cisco IOS rules (full CIS Level 1 coverage)
- Multi-vendor support (Juniper Junos, Arista EOS) via per-vendor rule files
- HTML report output
- Optional `nom`-based structured parser (sections, interfaces) for context-aware rules

## Status

Early. The rule engine and Cisco IOS starter set work; coverage is growing. Contributions and rule submissions welcome.

## License

Licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option. Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion shall be dual licensed as above, without additional terms.

---

*CIS references are indicative — always verify against the current CIS Cisco IOS Benchmark for your platform and version.*

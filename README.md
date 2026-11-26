# AuthLens

AuthLens is a browser-based security log triage workspace. It uses a Rust WebAssembly core to parse Windows Security `.evtx` files and Linux OpenSSH and auditd text logs, then places authentication, privileged-use, and selected account-management activity into one timeline.

**Try the web app:** https://augustx-ln.github.io/authlens/ (available after the first GitHub Pages deployment)

## What it does

- Parses multiple Windows Security `.evtx` and Linux `.log`/`.txt`/auditd files together in one case.
- Parses Windows Security event IDs **4624/4625** (logons), **4672** (special privileges), **4720/4722/4724/4725** (account lifecycle/password reset), and **4728/4732/4756** (group membership additions).
- Parses Linux OpenSSH sign-ins and `sudo` command records, plus auditd `ADD_USER`, `DEL_USER`, `ADD_GROUP`, `DEL_GROUP`, and `USER_CHAUTHTOK` records.
- Flags repeated failures for one account, password-spray patterns across accounts, and a successful login after related failures.
- Shows privileged use and account changes as timeline activity; account creation and group additions also create informational review findings.
- Shows an event timeline, searchable/filterable event table, finding details, and JSON/CSV export.
- Includes a synthetic log sample so the demo works without access to real systems or data.

## Privacy and limits

The deployed site is static. The selected log file is read by the browser and passed to the Rust WebAssembly analyzer in the same tab; AuthLens has no backend, analytics, or log upload endpoint. It does not store log contents in browser storage. Use only logs you are permitted to analyze, and avoid putting employer or customer data in public issue reports.

The combined case is limited to 25 MB and analysis is capped at 100,000 events. The report retains all parsed events and caps findings at 500, prioritizing high and medium severity first. Detection thresholds are intentionally simple and can produce false positives or miss activity. Findings are investigation leads, not proof of compromise. The Linux parser targets common OpenSSH/sudo messages and selected auditd record types; syslog timestamps have no year or timezone, so AuthLens uses the current year and displays them in the browser's local timezone. Auditd coverage depends on the host recording those event types. Windows event collection depends on the relevant audit policies being enabled. Other event types and formats are ignored.

## Run on Windows

Install Node.js 22 or newer and Rust. The Rust toolchain for Windows needs the Microsoft C++ build tools; the `wasm32-unknown-unknown` target and `wasm-pack` are also required.

From the repository root in PowerShell:

```powershell
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
.\scripts\build-wasm.cmd
Push-Location web
npm ci
npm run dev
Pop-Location
```

Open the local address printed by Vite. The generated WebAssembly package is intentionally built from the Rust source rather than checked into the repository.

## Architecture

- `crates/analyzer` — Rust parsers, normalization, detection rules, and the WebAssembly interface.
- `web` — React and TypeScript interface, file handling, visualization, filtering, and exports.
- `.github/workflows/pages.yml` — builds the Rust WebAssembly package and static website, then deploys it to GitHub Pages.

The detection thresholds are fixed in the source: five failed attempts against one account within ten minutes; at least eight failures across five accounts from one source within ten minutes; and a same-source, same-account success within thirty minutes after a failure. Related authentication events from separate files in one case are evaluated together.

## Detection references

- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1110.003: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [MITRE ATT&CK T1136: Create Account](https://attack.mitre.org/techniques/T1136/)
- [MITRE ATT&CK T1098.007: Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/)
- [Microsoft Windows advanced audit policy event reference](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Red Hat Enterprise Linux audit system guide](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)

## License

AuthLens is released under the MIT License. The EVTX parser dependency is dual-licensed under MIT or Apache-2.0; see its [upstream project](https://github.com/omerbenamram/evtx).

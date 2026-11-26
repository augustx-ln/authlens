# AuthLens

AuthLens is a browser-based security log triage workspace. It uses a Rust WebAssembly core to parse Windows Security `.evtx` files and Linux OpenSSH and auditd text logs, then places authentication, privileged-use, and selected account-management activity into one timeline.

**Try the web app:** https://augustx-ln.github.io/authlens/ (available after the first GitHub Pages deployment)

**Run the isolated live lab:** see [Docker lab](#docker-lab-kali-to-container) below. The live monitor runs on your laptop; the public GitHub Pages site remains the file-analysis demo.

## What it does

- Parses multiple Windows Security `.evtx` and Linux `.log`/`.txt`/auditd files together in one case.
- Parses Windows Security event IDs **4624/4625** (logons), **4672** (special privileges), **4720/4722/4724/4725** (account lifecycle/password reset), and **4728/4732/4756** (group membership additions).
- Parses Linux OpenSSH sign-ins and `sudo` command records, plus auditd `ADD_USER`, `DEL_USER`, `ADD_GROUP`, `DEL_GROUP`, and `USER_CHAUTHTOK` records.
- Flags repeated failures for one account, password-spray patterns across accounts, and a successful login after related failures.
- Shows privileged use and account changes as timeline activity; account creation and group additions also create informational review findings.
- Shows an event timeline, searchable/filterable event table, finding details, and JSON/CSV export.
- Includes a synthetic log sample so the demo works without access to real systems or data.
- Offers a downloadable public Windows Security `.evtx` sample in the upload panel.

## Privacy and limits

The downloadable `sample-security.evtx` is a 7-record clean Security log from the [evtx parser's public test corpus](https://github.com/omerbenamram/evtx/tree/master/samples), licensed with the parser under MIT/Apache-2.0. It includes event IDs 5152, 4611, 4776, 4625, 5157, and 4673. It is provided for parser practice; the existing synthetic sample report demonstrates AuthLens' detections.

The deployed site is static. The selected log file is read by the browser and passed to the Rust WebAssembly analyzer in the same tab; the public site has no backend, analytics, or log upload endpoint. It does not store log contents in browser storage. The optional Docker lab runs a local Rust server with in-memory activity records. Use only logs you are permitted to analyze, and avoid putting employer or customer data in public issue reports.

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

## Docker lab: Kali to container

This lab puts the target web page and seven TCP probe ports in a Docker container. AuthLens records connections and HTTP requests as they arrive. The monitor is published only on Windows `localhost:3000`; target ports 8080–8087 are published only on the Windows IP you select for Kali. No Windows event logging or log upload is required.

The event stream can download the latest 500 retained lab events as a valid `.evtx` file. These are synthetic `AuthLens-LiveLab` records in the Windows Application channel, not Security events collected from the host. AuthLens can read the exported file through its normal upload flow.

1. Start Docker Desktop in Linux-container mode. In PowerShell, find the Windows address on the network shared with Kali:

   ```powershell
   Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress
   ```

   For a Kali VM using VMware NAT, this is usually the `VMware Network Adapter VMnet8` address. Verify Kali can reach it. Use a host-only adapter instead if you want a network with no internet route. Do not use your Wi-Fi address for a private lab.

2. Install Node.js 22+, Rust, `wasm-pack`, and Docker Desktop if needed (same local build prerequisites as above). From the repository root, start the container:

   ```powershell
   .\scripts\start-lab.ps1
   ```

   The script builds the Rust WebAssembly analyzer and React frontend locally, then builds the small Rust lab image and opens the monitor. It selects the VMnet8 address automatically. For another lab adapter, pass its IPv4 address with `-LabBindIp`.

3. Open [the live monitor](http://localhost:3000/monitor) on Windows. From Kali, enter the target IP printed by the startup script when prompted:

   ```bash
   read -rp 'Windows lab IP: ' TARGET_IP
   curl "http://$TARGET_IP:8080/"
   nmap -sT -Pn -p 8081-8087 "$TARGET_IP"
   for endpoint in admin backup config debug login test secret status; do curl -s -o /dev/null "http://$TARGET_IP:8080/$endpoint"; done
   curl -A 'WhatWeb/0.5' "http://$TARGET_IP:8080/"
   ```

   The TCP scan produces a finding after four distinct probe ports in 30 seconds. Six distinct missing paths in 60 seconds trigger a path-enumeration finding. Twelve HTTP requests in 10 seconds trigger a rapid-probing finding, including successful requests. A high-priority correlated finding appears when a burst also includes six distinct missing paths or at least two methods rejected with `405`; it summarizes the request count, paths, and methods together. Known scanner User-Agents, common technology or exposure paths, traversal patterns, and uncommon HTTP methods (including `PUT`, `DELETE`, and `PATCH`) trigger a fingerprinting finding. Findings identify patterns, not a specific tool with certainty.

4. Stop the target when finished:

   ```powershell
   docker compose down
   ```

If Kali cannot reach port 8080, check that both systems share the VM network and that Windows Firewall permits inbound TCP 8080–8087 from Kali's IP on the selected adapter. Keep any firewall exception scoped to Kali's address and remove it after the lab.

The container sees connections to published ports only. A default Nmap SYN scan can complete without an application-level connection, and scans of unpublished or closed Windows host ports are outside this detector's view. Docker Desktop networking may present Kali traffic under a gateway IP; treat the displayed source as an observation from the container, not a guaranteed original IP. The detector ignores TCP connections during its first ten seconds because Docker Desktop may probe published ports at startup. Activity is held in memory (latest 500 events, latest 100 findings) and resets on container restart.

## Architecture

- `crates/analyzer` — Rust parsers, normalization, detection rules, and the WebAssembly interface.
- `web` — React and TypeScript interface, file handling, visualization, filtering, and exports.
- `crates/lab`, `Dockerfile`, and `compose.yaml` — isolated live target, scan-pattern detection, and a local monitor.
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

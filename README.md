# AuthLens

AuthLens is a browser-based authentication log triage workspace. It uses a Rust WebAssembly core to parse Windows Security `.evtx` files and Linux OpenSSH `auth.log`/`secure` text logs, then highlights a small set of suspicious sign-in patterns.

**Try the web app:** https://augustx-ln.github.io/authlens/ (available after the first GitHub Pages deployment)

## What it does

- Parses Windows Security event IDs **4624** (successful logon) and **4625** (failed logon).
- Parses Linux OpenSSH `Failed password`, `Accepted password`, and `Accepted publickey` records.
- Flags repeated failures for one account, password-spray patterns across accounts, and a successful login after related failures.
- Shows an event timeline, searchable/filterable event table, finding details, and JSON/CSV export.
- Includes a synthetic log sample so the demo works without access to real systems or data.

## Privacy and limits

The deployed site is static. The selected log file is read by the browser and passed to the Rust WebAssembly analyzer in the same tab; AuthLens has no backend, analytics, or log upload endpoint. It does not store log contents in browser storage. Use only logs you are permitted to analyze, and avoid putting employer or customer data in public issue reports.

Files are limited to 25 MB and analysis is capped at 100,000 matching events. Detection thresholds are intentionally simple and can produce false positives or miss activity. Findings are investigation leads, not proof of compromise. The Linux parser targets common OpenSSH auth log messages; syslog timestamps have no year or timezone, so AuthLens uses the current year and displays them in the browser's local timezone. The Windows parser currently extracts common fields from event IDs 4624 and 4625. Other event types and formats are ignored.

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

The detection thresholds are fixed in the source for this first release: five failed attempts against one account within ten minutes; at least eight failures across five accounts from one source within ten minutes; and a same-source, same-account success within thirty minutes after a failure.

## Detection references

- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1110.003: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

## License

AuthLens is released under the MIT License. The EVTX parser dependency is dual-licensed under MIT or Apache-2.0; see its [upstream project](https://github.com/omerbenamram/evtx).

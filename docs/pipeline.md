# steam-monitor pipeline

Every 15 min CI polls the stable + beta win64 manifests. On a new build it
downloads the DLLs, re-resolves all hook signatures from scratch, and
publishes per-SHA TOMLs. Same entry schema as the legacy feed
(`[FNV-hash] / name / rva / sig`), so the client only needs a URL swap.
IPC interface data goes to `ipc/steamclient/<sha>.toml` in the upstream IPC
schema (`interface_id` / `vtable_rva` plus per-method `method_index` /
`funcHash` / `wrapper_rva` / `fencepost` / `argc`).

1. `tools/fetch_client.py` → `bins/<channel>/` (exit 2 = already published, skip)
2. `tools/resolve_patterns.py` → `pattern/<side>/<sha256>.toml` (any FAIL = nonzero exit)
3. `tools/resolve_ipc.py` → `ipc/steamclient/<sha256>.toml` (any FAIL = nonzero exit)
4. Any FAIL → nothing published, an issue is filed, re-run via `workflow_dispatch`
5. On success: `README.md` is re-rendered (knap, do not hand-edit) and committed with `pattern/` + `ipc/`

Blocked-run triage notes:
- Duplicate prevention: one open issue per beta SHA pair; a green publish
  closes leftover issues whose title SHAs are now published.
- `steamclient` anchor collisions: candidates can be pinned by prologue
  bytes via `PROLOGUE_PINS` in `tools/resolve_patterns.py` (worked example:
  the 1792192922 beta twins for `CUtlBufferEnsureCapacity`).
- `DepotLicenseGate` is resolved through the `BuildDepotDependency` logical
  function: follow chained x64 `.pdata` records, collect calls across its hot
  and cold fragments, then select the unique direct callee that also calls the
  separately resolved `CheckAppOwnership`. This avoids a version-specific RVA,
  prologue, or function-size pin. Calls are instruction-decoded inside exact
  `.pdata` ranges; malformed/cyclic chains and missing or ambiguous topology
  fail closed and must be reviewed before publishing that build.
- IPC funcHash/fencepost re-rolls: methods derive their two serialized u32
  constants from the wrapper selected through that build's vtable. `GetSteamID`
  has a narrow channel-seed fallback for codegen variants the extractor cannot
  decode; chained `.pdata` fragments are included before fallback, and the
  seed is used only if the selected wrapper family contains that funcHash.
  Other extraction failures print the exact `.pdata` extent and bounded
  disassembly to the Actions log.
- Phase-2 window misses: `p2_findcreate` scans the 64KB page holding
  `KeyValues_ReadAsBinary`, assuming the KeyValues helpers stay on one page.
  When the block shifts and the two land on opposite sides of a boundary
  (1792711043 beta: `ReadAsBinary` at 0xDA0AE0, `FindOrCreateKey` at
  0xD9DEC0), the window is empty and the picker falls back one page down.
  A `0 <name> cands` failure from a phase-2 rule is worth checking against
  page alignment before touching thresholds or anchors.
- Issue filing needs the repository's Issues feature enabled. With issues
  disabled, `gh issue list` and `gh issue create` return 410 and the triage
  step fails on its own, hiding the resolve failure it exists to report.

No TOMLs are shipped or fetched — every hook derives from the DLLs alone.
`tools/migrate_patterns.py` is a seed-era analysis aid, not in the pipeline.

## Local run

```sh
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests
python3 tools/fetch_client.py --out bins/ --channels stable beta
python3 tools/resolve_patterns.py resolve \
  --dll bins/stable/steamclient64.dll --side steamclient --out-dir pattern/
python3 tools/resolve_ipc.py resolve \
  --dll bins/stable/steamclient64.dll --channel stable --out-dir ipc/
```

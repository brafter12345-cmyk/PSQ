# Integration inventory — 2026-11-02

## Scope and status

This is a technical inventory for the local integration review. It records accepted local work only; it is not a live-release, push, master-merge, or deployment record. The integrated sandbox lineage is root `712a289` with the earlier remediation checkpoint `4116dd3`; the local merge checkpoint is `b6a3c05`.

The main worktree remains at `c0ffe7b`. Its verified status shows one modified file, `security_scanner/docs/OUTSTANDING.md`, and five untracked directories: `_handover_assets_2026-09-15/`, `attachments/`, `email-signature/`, `tmp/`, and `xneelo-ssh/`. The main OUTSTANDING file was preserved in an exact backup recorded under hash prefix `5495...`. Canonical asset-discovery item 5n is retained in the integration register; the whole integration register is not byte-identical to that backup. The ref inventory recorded 52 local refs and 10 remote refs at review time. These are inventory counts, not a claim that every ref is part of this integration.

Unknown production controls remain unknown. This record makes no per-user-authentication claim. Runtime checkpoint `6e91167` follows `b6a3c05`; master and live remain unchanged.

## Integration update 2 November 2026

The local integration includes merge checkpoint `b6a3c05` and runtime checkpoint `6e91167`; master and live remain unchanged. Six dashboard fetches now carry the existing scanner API key, reject cross-origin paths and fail closed on redirects. The key is embedded in the results HTML under the existing edge access model; this is not per-user authentication. Synthetic tests cover provider failure and retry behavior, but do not implement IntelX balance integration, which remains open. An authorized isolated fresh `npm ci` passed, and the pinned pre-change `/scanner` bundle reproduced the committed JavaScript and CSS byte for byte. At runtime checkpoint 6e91167, all 12 final offline gates passed; five card and four origin targeted mutations were caught by assertions with no crashes. Paid-egress attempts and offline blocked operations were zero; DATABASE_URL was unset and port 5544 had no listener. The full 347-mutation rerun detected all 347: 345 by assertions and two by gate crashes (X01_probe_gets_raw_list: NameError; R13_api_door_whole_entry: IndentationError); no mutations survived. All six baseline gates had zero failures; all six mutation processes exited zero. A separate audit of 442 offline-guard records from 18:13:44 to 18:54:49 local found zero blocked operations and no DATABASE_URL set at exit; six owned-loopback fixture operations were recorded. The sweep contained 347 unique mutation labels.

The owner decided to keep scoring unchanged and record the gaps. Synthetic reproduction identified VirusTotal and SecurityTrails rate limits, entirely unanswered information-disclosure and dependency-manifest probes, and truncated VPN probing with confirmed RDP. The current weights, baselines and scoring/checker policy remain unchanged; no expected-loss change has been implemented. The counterfactual below excludes each affected category's weight in isolation, using the actual scoring and insurance pipeline on synthetic R10m revenue. It is a policy experiment, not a premium or a golden-fixture impact. Whole-category exclusion loses part of the positive RDP contribution and is not an approved evidence-preserving policy.

| Synthetic case | Risk current → counterfactual | Completeness | Expected annual loss ZAR current → counterfactual | PML 1-in-250 ZAR current → counterfactual |
|---|---:|---:|---:|---:|
| VirusTotal 429 | 252 → 262 | 100% → 97% | 207,915 → 211,723 | 12,708,688 → 12,708,688 |
| SecurityTrails 429 | 264 → 266 | 100% → 97% | 212,498 → 213,279 | 12,708,688 → 12,708,688 |
| VPN truncated, RDP confirmed | 283 → 275 | 100% → 97% | 366,229 → 362,976 | 12,708,688 → 12,708,688 |
| Information disclosure unanswered | 252 → 262 | 100% → 97% | 207,915 → 211,723 | 12,708,688 → 12,708,688 |
| Dependency manifests unanswered | 255 → 263 | 100% → 97% | 209,045 → 212,111 | 12,708,688 → 12,708,688 |

## Excluded work and provenance checks

- No extra commit candidate was accepted. The two previously identified candidates (`53b2c5e` and `4a7701c`) were superseded/equivalent historical work and were not cherry-picked.
- Dirty frontend/form material was excluded. The legacy lead UI includes a direct external form submission target and was not integrated; generated/client-facing artifacts were not treated as scanner production code.
- The dirty `interesting-jennings` manual DOCX is byte-identical to its HEAD blob (same 123,687-byte artifact and document XML hash). It contributes no new content; the newer integration-generated manual remains authoritative.
- Calibration helpers were excluded because their intended logic is already shipped in the integration (`FINE_CAPACITY_FLOOR=0.80` and revenue elasticity). Diagnostics and research scripts were not promoted to production.
- The duplicate legacy `security_scanner_sarel` tree was inventoried using safe source extensions while excluding environment, credential, cache, fixture, client-data, generated, archive, spec, node-module, and virtual-environment paths. Of 62 safe files, 48 matched reachable historical blobs, 8 matched current integration plus history, and 6 were unique legacy generators/UI assets. The six unique files were report generators and a lead/quote UI (`generate_blackkite_comparison.py`, `generate_comparison_pdf.py`, `generate_sa_breach_costs.py`, `index.html`, `script.js`, `style.css`); none was accepted, deleted, or wholesale integrated.

## Boundaries and pending work

Root review completed for the bounded local integration. Authorized isolated fresh npm ci passed; the pinned pre-change /scanner JavaScript and CSS reproduced the committed bundle byte for byte. Six dashboard fetches use the existing key, reject cross-origin paths and fail closed on redirects; the key in results HTML relies on the existing edge model and is not per-user authentication. Provider failure and retry tests were added; IntelX balance integration remains open. The final 12 offline gates passed at 6e91167; the full mutation results are recorded above. Live providers, production databases, credential export, push, merge into master, and deployment remain out of scope.

This inventory does not close unknown production controls, provider reliability/coverage, attribution/apex/PSL behavior, or per-user authorization. Follow-up review must preserve those open questions rather than infer closure from local integration status.

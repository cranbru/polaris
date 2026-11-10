# POLARIS project review and improvement roadmap

Reviewed on 10 November 2026. This review covers the acquisition engine, collectors, parsing, timelines, rules, correlation, AI, case management, CLI, reports, manifests, archives, packaging, and tests.

## Assessment

POLARIS has a useful product direction: portable Windows triage that produces evidence, a timeline, explainable findings, and an investigation package. Its modular structure is a good base for further development. The highest-value next investment is making every conclusion reproducible and every acquisition outcome accurately reported.

The source tree contains 122 tracked Python files and approximately 12,056 Python lines, including tests, with 25 registered collector modules and six built-in heuristic rules. The Quick profile currently selects 11 modules, including the sensitive-file collector.

I ran `.venv/Scripts/python.exe -m pytest -q -m "not integration"`: **58 passed**, with one locale deprecation warning. I also exercised the behaviors below using temporary synthetic cases, fake credentials, and mocked acquisition/provider calls. These checks validate software behavior; they do not establish accuracy across Windows versions. A full live acquisition, real cloud-provider calls, and a newly compiled executable were outside this review's validation scope.

## What is already worth keeping

- Acquisition, analysis, reports, AI providers, and archive construction have separate modules.
- Pydantic models provide a starting point for explicit data contracts.
- Findings distinguish grounding, severity, confidence, alternative explanations, and validation steps.
- SHA-256 calculation streams file content, and manifest verification detects changes and missing files.
- The collector base captures exceptions, allowing a run to retain partial results.
- Browser collectors use an artifact allowlist, and saved AI configuration excludes session API keys.
- The portable output directory and offline option fit incident-response deployment.

## Recommended order

| Order | Improvement | Expected benefit |
|---|---|---|
| 1 | Accurate acquisition, verification, and completion status | Investigators can trust what the tool says it accomplished |
| 2 | Complete, portable, verifiable evidence packages | Cases survive transfer to another examiner or device |
| 3 | A shared event schema and correct timestamp handling | Existing collected artifacts become useful timeline and detection inputs |
| 4 | Immutable evidence and durable investigation state | Reports and reanalysis preserve provenance and examiner work |
| 5 | Correct AI inputs, controls, and evidence citations | AI assessments actually reflect the acquired case |
| 6 | Sensitive-data handling across acquisition and exports | Evidence can be shared without accidental secret disclosure |
| 7 | Deeper parsers and stronger correlation | Better investigative coverage and fewer misleading findings |
| 8 | Artifact fixtures, Windows CI, and reliable releases | Improvements remain dependable as the project grows |
| 9 | Search, filtering, case comparison, and incident profiles | Faster practical investigations |

## Concrete findings and fixes

### 1. Success and integrity claims must follow actual outcomes

**Confirmed:** `cli/app.py:274` always displays “Cryptographically Sealed & Verified (ISO/IEC 27037)” in the final panel. A mocked run with verification, report generation, and archive construction failures still displayed that claim. Broad exception handling lets later stages continue, but the final panel does not reflect the failed stages.

**Confirmed:** `collectors/eventlogs/evtx_collector.py:98` increments successful exports after `_export_evtx()` returns. That function returns normally for command failures and missing channels. When all ten mocked export commands failed, the collector returned `SUCCESS` with zero files and ten warnings.

Introduce typed results for each acquisition operation and pipeline stage. Distinguish unavailable artifacts, permission failures, successful empty queries, parsing failures, and partial acquisition. Persist the resulting stage summary and meaningful process exit code. Require a completed verification with no integrity discrepancies and a complete archive inventory before reporting a verified package.

Keep the live-acquisition limitation visible. Hashes establish byte consistency against a baseline; broader forensic-standard claims need documented procedures and validation.

**Acceptance checks:** an all-failed export is never successful; verification failure appears in CLI, metadata, and reports; an incomplete archive cannot be labeled complete; zero acquired artifacts are explained explicitly.

### 2. Archive filtering currently removes evidence

**Confirmed:** `archive/zip_builder.py:35` excludes files based on substrings including `.env`, `secret`, `token`, and `archive`. A synthetic case with manifested `.env`, `secrets.txt`, `tokens.txt`, and `archive_notes.txt` omitted all four from its ZIP. The archive was nevertheless labeled `SEALED`. Write failures are also swallowed at line 67.

These filters conflict directly with the sensitive-file collector. A manifest can list evidence that the delivered ZIP does not contain.

Build the evidence portion from an explicit evidence inventory. Exclude POLARIS operational configuration by its known location, rather than by substrings in evidence names. Record every exclusion and failure, and reconcile expected entries against actual ZIP entries before completion. Construct archives atomically and verify their contents and checksums.

**Confirmed:** `core/manifest.py:116` verifies the stored `acquired_path` directly. A manifest used from a different case location still checked the original evidence location when that location remained accessible. Absolute acquisition paths are unsuitable as the authoritative locator for a portable package; relative paths also depend on the process working directory.

Store a case-relative evidence path separately from the original source path. Resolve it against the case being verified, enforce containment within that case, and reject traversal or unexpected external locations. Hash derived outputs in a separate inventory too: several collectors save parsed JSON without adding it to `acquired_files`, so the current manifest coverage varies by collector.

**Acceptance checks:** extract a package elsewhere, make the original unavailable, and verify successfully; tamper with the extracted evidence and detect it; account for every manifested file; test disk-full and interrupted ZIP writes.

### 3. Replace field guessing with a normalized event contract

**Confirmed:** `core/timeline.py:78` recognizes a limited set of timestamp keys. It omits fields actually emitted by collectors, including:

- Prefetch: `source_modified` and `source_created`.
- BAM/DAM: `last_execution_time`.
- LNK and Jump Lists: `creation_time`, `modification_time`, and `access_time`.
- Recycle Bin: `deletion_time`.
- Chrome/Edge: `last_visit_time`.
- Firefox: `last_visit_date` and `visit_date`.
- Scheduled Tasks: `last_run_time`.

Synthetic records using these fields did not enter the timeline. In addition, events are sorted as strings at line 50. Mixed timezone offsets produced the wrong chronological order in a synthetic example.

Create artifact-specific adapters that emit a shared event model: stable event ID, raw evidence ID, source record ID, source field, event type, UTC timestamp, original timestamp, timezone interpretation, precision, user identity, and relevant process/file/network/device fields.

Allow one source record to produce several events with different meanings. A shortcut target's creation time, a browser visit, and an observed process execution should retain their distinct semantics. Preserve unknown timezone or date-only precision instead of fabricating exact instants. Keep records without timestamps available for search even when they cannot enter a chronological timeline.

**Acceptance checks:** use actual collector-output fixtures for every adapter; test UTC/local time, daylight-saving changes, offsets, date-only values, invalid timestamps, and repeated normalization.

### 4. Parse preserved evidence and retain acquisition provenance

Several collectors parse the live source after copying it. Prefetch calls its header parser on `pf_path`; LNK, Jump List, PCA, and Recycle Bin parsing likewise reads source paths. Chrome, Edge, and Firefox fall back to live databases when the acquired database is missing. Event logs are exported, then independently queried from the live channel.

The source may change between acquisition and parsing, making findings impossible to reproduce from the delivered evidence. Browser database/WAL files are copied separately; consistent SQLite snapshots and WAL handling also need explicit validation. Parsing should use a disposable working copy where database recovery can modify files.

Centralize acquisition: record the source, acquisition method, operation start/end times, relevant source metadata, bytes captured, and SHA-256 before parsing. Record fallback methods such as registry export or VSS-assisted copy accurately. Parse the preserved bytes or a documented derivative, and attach parser name/version/configuration to each output.

Collect volatile process and network state early. They currently appear late in the profile order, after slower file and registry collectors. Record actual observation times for individual snapshots and link connections to process identity and start time to reduce PID-reuse errors.

**Acceptance checks:** changing the live source after capture cannot change parsing results; preserved raw bytes remain unchanged; every normalized event resolves to a captured artifact and source record.

### 5. Reports must preserve findings and examiner decisions

**Confirmed:** `reports/html_report.py:46` reruns `RulesEngine.run_all_rules()`, which overwrites `metadata/findings.json` at `analysis/rules/__init__.py:51`. Findings get random IDs on each run. A synthetic reviewed finding with a benign status and an investigator note disappeared after HTML report generation. Saved correlation findings can also disappear from that file because the report reruns correlation only for its local result.

PDF generation invokes HTML generation again, multiplying this work. HTML also passes `findings=[]` to the template at line 112, so deterministic findings are unavailable in that report's findings input. The comment records an earlier presentation preference; any change to visible report sections should respect that preference, while preservation of investigation data should be unconditional.

Use versioned analysis snapshots and stable finding identities derived from rule/version/source-record identity. Store annotations and review decisions independently from generated detections. Reports should read a chosen snapshot, and explicit reanalysis should create a new version without discarding annotations. Complete the case metadata lifecycle with stage states, completion time, totals, and run identity.

**Acceptance checks:** repeated reports preserve findings, notes, statuses, and IDs; correlation findings remain saved; an examiner can compare two analysis versions.

### 6. AI currently loses important case inputs

**Confirmed:** `ai/prompts.py:32` accepts `rule_findings` but never includes them in the prompt. A unique synthetic finding marker was absent from the generated prompt. The analyzer's `evidence_reference_count` nevertheless counts those findings.

**Confirmed:** the smart-evidence extractor expects Prefetch fields such as `executable` and `last_run_time`, while the built-in collector emits `executable_name` and `source_modified`. Actual-shaped synthetic output generated an execution summary with `None` values. Prefetch modification time should not be substituted for a parsed execution timestamp.

**Confirmed:** network records contain `protocol`, `local_addr`, and `remote_addr`, but AI extraction/prompt rendering expects `proto`, `local_address`, and `remote_address`. A synthetic external IP vanished from the rendered AI prompt. The prompt also omits the extracted UserAssist section. Sampling the first 30 timeline events after ascending sort tends to emphasize old activity, not the investigator's incident window.

Use the normalized schema to construct a bounded evidence packet containing referenced findings, relevant events, source IDs, collection gaps, and verification status. Save a sanitized request snapshot or digest, sampling policy, omitted-record counts, model, prompt version, response, and fallback reason. Use an incident time window and explain the sampling strategy.

Add structured AI findings with required evidence references. Validate referenced IDs, timestamps, and hashes against the case before treating them as grounded; label unsupported assertions explicitly. Delimiter escaping and prompt-injection tests should complement this validation. The current wrapper permits an embedded closing `</forensic_evidence>` tag; regex filtering is not a guarantee of instruction isolation.

### 7. Offline output and AI settings need reliable semantics

**Confirmed:** `ai/providers/offline_provider.py` returns the same fixed prose for different case inputs, including an unconditional claim that all artifacts were verified. Inputs describing zero artifacts and failed verification still produced the same success-oriented text.

Generate offline summaries from actual findings, acquisition counts, timeline coverage, verification results, and limitations. If no analysis exists, say so. Preserve the reason for online fallback: an attempted cloud request followed by a local fallback should not be described as a run that made no external requests.

**Confirmed in a mocked pipeline:** `AISettings.enabled=False` did not prevent analysis; revoked consent was set back to true; and a saved offline provider was replaced by an online provider when a fake environment key existed. `execute_mission()` defaults `consent=True`, and interactive configuration also treats declining configuration as consent.

Separate configuring credentials from authorizing transmission. Honor disabled AI, revoked consent, and explicit offline selections through every entry point, including report generation. Persist scoped authorization with the chosen case/provider or an explicit user-configured policy. Use hidden API-key input, validate model settings, and handle empty responses and provider errors distinctly. Audit default model identifiers and centralize their configuration; provider availability was not checked during this review.

**Acceptance checks:** offline and disabled modes make zero provider calls; declined consent stays declined; a request captured by a fake provider contains the intended finding and source references.

### 8. Sensitive collection needs separate handling in reports and packages

**Confirmed:** `reports/evidence_inspector.py:126` treats `.txt`, `.csv`, and `.json` files in the evidence directory as report-preview candidates. A synthetic `passwords.txt` had its content included in the preview. Being an acquired text file does not mean it is safe to embed in an ordinary shareable report.

**Confirmed:** the redaction patterns left quoted JSON passwords, a synthetic hyphenated API-key format, and a URL token unchanged. Collector allowlists for browser credential databases do not protect secrets in command lines, histories, URLs, raw hives, or the sensitive-file collector.

Add sensitivity metadata at acquisition and carry it through all derivatives. Keep raw evidentiary bytes intact, but produce redacted report and AI views. Offer an explicit sensitive-collection scope and encrypted full-evidence packaging. Preserve useful correlations through deterministic pseudonyms where appropriate. Make the privacy notice accurately describe collected data.

The sensitive collector also hashes matched files before applying the copy-size cap. Its 100 MB storage cap does not bound bytes read, scan duration, file count, or memory used by `seen_paths`. Quick currently includes a recursive scan of user directories and non-C drives. Add configured roots, drive-type checks, read/time budgets, cancellation, and an explicit policy for oversized-file hashing. Exclude the actual output directory by resolved path, rather than assuming it is named `cases`.

### 9. Parsing depth and detection coverage should be explicit

The 25 collector count is useful acquisition coverage, but parser depth varies substantially:

- Built-in Prefetch parsing identifies headers and compression; it does not extract run counts or execution times. PECmd is an optional integration, and its CSV output is not normalized into the JSON-based timeline/rules pipeline.
- Amcache and SRUM outputs explicitly defer full parsing to external tools.
- ShimCache and ShellBags acquisition exports data without a semantic parser.
- UserAssist decodes names but does not decode execution counts and FILETIME values.
- Jump List parsing skips the DestList stream and does not parse CustomDestinations semantically.
- Chrome/Edge history queries summarize the URL table rather than extracting all individual visits.
- Event logs use localized text output with a 5,000-event cap rather than parsing the acquired EVTX with structured XML/EventData.

Publish a capability matrix separating acquisition, semantic parsing, timeline support, rule support, and tested OS/artifact versions. Integrate mature parsers through one registry with version/hash provenance, normalize their outputs, and report parser failures independently of successful acquisition. Prioritize EVTX, Prefetch, BAM/UserAssist, and browser visits because existing features depend on them.

**Confirmed schema mismatches:** scheduled-task output uses `task_to_run`, which its rule does not inspect; event-log output uses `Message`, which the encoded-PowerShell rule does not inspect; LNK target and arguments are separated, which prevents the tested LOLBin rule from identifying their combined invocation. BAM SID parsing expects `HKLM\\` headers although Windows `reg query` emits `HKEY_LOCAL_MACHINE\\`.

Test parser outputs against their downstream consumers, rather than testing each component with independently invented dictionaries.

### 10. Correlation and heuristic wording need stronger evidence semantics

**Confirmed:** `analysis/correlation.py:43` derives category from a parsed file's immediate parent. Real paths include nested directories such as `parsed/execution/prefetch` and `parsed/network/network`; those names do not consistently identify artifact categories. The executable extractor ignores service `binary_path` and Run-key `command` fields. Actual-shaped process and Run-key fixtures produced no execution/persistence correlation.

When correlation does match, it uses executable names without confirming normalized full path, hash, user, or incident time. Its description overstates what name co-occurrence establishes. Removable-media analysis also assumes drive letters outside C/D identify external storage without proving the device/volume mapping.

**Confirmed:** a synthetic shortcut pointing to `Downloads/meeting_notes.docx` generated a high-severity OBSERVED finding stating that an executable had launched. The suspicious-path rule runs over arbitrary record types and treats a target path as execution evidence.

Introduce typed entities and rules scoped to supported event types. Separate observed configuration or file references from observed execution. Join processes/persistence by normalized path or stronger identifiers, time, and user; join USB activity by volume/device identifiers and session evidence. Allowlist verified administrative behavior and calibrate severity with realistic benign cases. Add versioned rule metadata and explicit ATT&CK technique IDs.

### 11. Packaging and validation need a clean-machine path

**Confirmed:** the configured backend `setuptools.backends._legacy:_Backend` in `pyproject.toml:3` cannot be imported in the existing environment (`ModuleNotFoundError: setuptools.backends`). Use the supported `setuptools.build_meta` backend.

Package discovery excludes `ai` and `archive`, includes a `packaging*` pattern although the application uses `archive`, and does not explicitly declare report-template package data. Verify the `main` console entry module too. Runtime version is 2.0.0 while project metadata says 1.0.0. The executable spec imports Pillow and collects pyfiglet, but those are not declared build dependencies. These are release-configuration issues to resolve and validate with installed-wheel and executable smoke tests.

Add Windows CI for supported Python/Windows versions, a sanitized artifact-fixture corpus, installation tests, and frozen-executable smoke tests. Test locked files, permission denial, missing channels, malformed artifacts, non-English output, Unicode paths, low disk space, case relocation, and interruption. Use realistic positive and negative detection examples. Existing report tests mostly check existence/content markers, and the ZIP test checks a simple benign file; they do not catch the correctness failures above.

Unify dependency definitions, lock release inputs, publish release checksums and build metadata, and consider Authenticode signing for portable distribution. Make administrator elevation depend on the command: reading findings, settings, reports, and verification should not need blanket elevation. Validate case IDs, reject path traversal, and explicitly distinguish a new acquisition from resuming an existing case.

## Product features after the correctness work

| Feature | Why it helps | Dependency |
|---|---|---|
| Searchable local case explorer | Filter records by incident window, user, path, process, IP, and artifact; open the underlying evidence | Stable event schema and provenance |
| Finding review commands/UI | Add notes, mark benign/confirmed, and persist decisions | Durable annotations and finding identities |
| Incident profiles | Select acquisition by objective: ransomware, persistence, USB activity, browser compromise | Explicit capability matrix and configurable scope |
| Case comparison | Show new services, tasks, users, binaries, and network destinations against a baseline | Normalized entities and versioned snapshots |
| Sigma-compatible rules and YARA integration | Expand reproducible behavioral/file detections | Stable schemas, rule versioning, realistic evaluation corpus |
| Filesystem artifact support | Add MFT, USN Journal, and relevant NTFS metadata for file creation, rename, and deletion investigations | Safe acquisition and mature parsers |
| Process lineage and identity | Relate process creation, parentage, persistence, and network activity | Structured event logs and timestamped volatile snapshots |
| Optional memory acquisition/import | Extend investigation of fileless activity | Explicit deployment scope and specialist-tool integration |
| Local-model provider | Offer language-model assistance for restricted environments | Validated evidence packets and existing provider interface |
| Redacted sharing and encrypted full packages | Give examiners useful exports for different audiences | Sensitivity labels and complete archive inventories |

The HTML report currently renders static previews, the first 40 timeline events, and the first 30 manifest entries. The next investigation interface should expose completeness counts, search/pagination, filters, and links from a finding to its source record. Keep the executive report readable while retaining full machine-readable exports.

## A practical release roadmap

**First milestone — trustworthy output:** fix operation/stage statuses, archive omissions, portable manifest paths, note loss during report generation, AI enable/consent behavior, and sensitive preview leakage. Add regression coverage for each confirmed failure.

**Second milestone — trustworthy analysis:** introduce the event contract, normalize existing collector outputs, use UTC-aware ordering, parse acquired evidence, include deterministic findings in AI packets, generate truthful offline summaries, and repair rule/correlation integration.

**Third milestone — investigator efficiency:** deepen the highest-value parsers, add an artifact capability matrix, launch a searchable local case explorer, expose annotation workflows, and add incident profiles. Establish Windows CI and clean-install/release checks alongside this work.

Measure progress by supported fixtures successfully normalized, events linked to raw records, archive completeness, case relocation verification, preservation of annotations, and precision/recall on realistic detection examples. Those measures will make additional collectors and AI features valuable instead of increasing unvalidated output.

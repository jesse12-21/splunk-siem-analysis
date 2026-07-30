# Known Limitations

Findings from building this content against contentctl, Splunk's own content tool. Each entry records what was tested, what was observed, and what was done about it.

The premise: a detection you have not compiled is a detection you have not written. YAML that looks correct fails validation for reasons that only surface when a real tool parses it.

---

## 1. contentctl requirements that are not obvious from the schema

Building the first detection surfaced six validation failures in sequence. Each was legitimate; none was guessable from reading an example file.

**The filter macro name is derived from the detection name, not chosen.**

```
❌ Detection does not contain the EXACT filter macro
   `botsv1_excessive_failed_logons_from_single_source_filter`
```

The macro must be the detection's `name` field, lowercased with underscores, suffixed `_filter`, and it must appear in the search. Renaming a detection therefore means renaming its macro.

**The file name must also match the name field.**

```
❌ The file name MUST be based off the content 'name' field
```

**`threat_objects` is required, not optional.** Omitting it entirely produces a confusing error that reports the whole `rba` block as missing:

```
⚠️ Field Required: rba
```

An empty list satisfies it. Detections where the scored entity is the only object of interest should use `threat_objects: []` rather than dropping the key.

**Valid `risk_object` types are `system`, `user`, `other` — and that is all.** `threat_object` types come from a separate, longer vocabulary that notably does **not** include a user. A targeted account cannot be a threat object; if you want to score it, it is a second risk object.

**Two drilldown searches are required, not one.**

```
❌ This detection is required to have 2 drilldown_searches, but only has [1]
```

**Every referenced object must exist.** `analytic_story`, `data_source`, and the deployment matching the detection's `type` all resolve at validation time. A `type: Anomaly` detection needs a deployment named `ESCU Default Configuration Anomaly` present in `deployments/`.

**Twelve directories must exist even when empty** — `deployments`, `baselines`, `investigations`, `playbooks`, `data_sources`, `dashboards`, `lookups`, `stories`, `macros`, `detections`, `removed`, `dist`. contentctl fails on a missing directory rather than treating it as empty.

---

## 2. Production detections require tests, and BOTSv1 cannot supply them

```
❌ At least one test is REQUIRED for production detection
```

contentctl's testing framework replays `attack_data` samples against a containerised Splunk instance. That is the right model, and it does not fit this content:

- BOTSv1 is a 33.4-million-event corpus. It cannot be committed, and `.gitignore` excludes it.
- No sample in Splunk's public `attack_data` repository exercises the specific data-model paths these detections use.

Reading the validator source shows the sanctioned alternative:

```python
# Manually tested detections are not required to have tests defined
tags: DetectionTags | None = info.data.get("tags", None)
if tags is not None and tags.manual_test is not None:
    return v
```

Every detection here therefore carries `tags.manual_test` with a specific statement of how it was validated and why automated testing is absent. **This is a real gap, not a solved problem.** These detections have been validated by hand against BOTSv1 and compiled by contentctl. They have not been proven to fire on replayed attack data in CI, which is a weaker guarantee than the Suricata companion project achieves.

---

## 3. `.gitignore` and lookup files

The repository's `.gitignore` excluded `*.csv` — reasonable, since Splunk data exports are CSVs and can be large.

contentctl lookups are also CSVs. A lookup excluded from the checkout resolves as a missing reference and fails validation on a clean clone while passing locally, because the file is present on the developer's machine.

This exact failure mode cost several CI iterations in the [suricata-ids-rules](https://github.com/jesse12-21/suricata-ids-rules/blob/main/docs/known-limitations.md) project, where a `datasets/*.txt` rule excluded the dataset files the rules depended on. It was fixed here before it could occur:

```
*.csv
!lookups/*.csv
```

CI also verifies the required directories are present in the checkout before validating, so a future recurrence names the missing file rather than surfacing as a reference-resolution error.

**The general point: a detection repository has runtime data dependencies, and version control must distinguish data that is generated from data that is required.**

---

## 4. What CI validates, and what it does not

| Validated | Not validated |
|---|---|
| YAML schema conformance | That the SPL returns results |
| Macro and object reference resolution | That data model names exist in your Splunk |
| RBA block structure and serialisation | That field names match your CIM mapping |
| Compilation to installable `.conf` files | Detection efficacy or false-positive rate |
| ATT&CK tag presence, ID uniqueness | Search performance |

The distinction matters. **contentctl can tell you a detection is well-formed. It cannot tell you it is correct.** A detection searching `datamodel=Authentication.Authentication` for a field that your add-on does not populate will validate, build, deploy, and never fire. Only a live Splunk instance with real data catches that, which is why every detection carries a `how_to_implement` field naming its data prerequisites.

---

## 5. Detection coverage gaps

| Gap | Affects | Detail |
|---|---|---|
| **Data model acceleration required** | All `tstats` detections | Without acceleration these return nothing. Not an error — silently empty results, which is worse. |
| **CIM add-ons required** | All detections | Detections search normalised fields. Without the relevant TA installed, the data models are empty. |
| **URL encoding** | SQL injection detection | Literal string matching is bypassed by percent-encoding and comment insertion. This catches unobfuscated attempts only. |
| **Suricata severity mapping** | IDS detection | Suricata emits numeric 1–3 with 1 as most severe; the CIM mapping inverts this. Verify before relying on a severity filter. |
| **Encrypted traffic** | Web detections | Web data model content requires decrypted traffic or proxy logs. |
| **No decay window verified** | RBA generally | Risk accumulation without decay means long-lived hosts eventually cross any threshold. ES applies a window; this content does not configure one. |
| **Threshold values are BOTSv1-derived** | All detections with thresholds | 20 failures, 100 not-founds, 50 unique URLs — tuned against one dataset. They are starting points, not production values. |

---

*Findings recorded while building against contentctl 5.5.16 with Python 3.12. CI validates and builds on every push.*

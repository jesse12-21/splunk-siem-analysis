# Integrations

This project is the SIEM layer of a three-repository detection pipeline. Rules are authored and validated where the protocol expertise lives, then converted or ingested here for correlation and risk scoring.

```
wireshark-threat-detection          suricata-ids-rules
  Sigma rules                         Suricata rules → EVE JSON
        │                                     │
        │ contentctl convert                  │ inputs.conf / props.conf
        ▼                                     ▼
              splunk-siem-analysis
         contentctl YAML → risk events → RBA
```

---

## 1. Sigma rules from the Wireshark project

The [wireshark-threat-detection](https://github.com/jesse12-21/wireshark-threat-detection) project maintains seven active Sigma rules covering DNS tunneling, TLS/ECH anomalies, post-quantum capability mismatch, and AI/MCP egress. Sigma is SIEM-agnostic by design, and contentctl has native support for Sigma detection rules.

### Converting

```bash
# From a clone of the Wireshark project
sigma convert -t splunk --without-pipeline \
  detections/sigma/dns_long_query.yml
```

Note the `--without-pipeline` flag. There is no published Zeek pipeline plugin for pySigma, so the conversion emits Sigma's field names unchanged — which is correct here, because those rules are written against Zeek's schema. The detail and the reasoning are in that project's [`known-limitations.md`](https://github.com/jesse12-21/wireshark-threat-detection/blob/main/docs/known-limitations.md).

### What conversion does not do

A converted Sigma rule produces a *search string*. It does not produce a contentctl detection. To bring one into this repository you still need to:

1. Wrap the search in the required structure — `_filter` macro at the end, `security_content_summariesonly`, data model references if you want acceleration.
2. Add an `rba` block. Sigma has a `level` field, but it maps to severity, not to a risk score. The two are different things — see [`rba-guide.md`](rba-guide.md).
3. Map the log source. A Sigma rule targeting Zeek `dns` needs a corresponding Splunk sourcetype and, ideally, a CIM mapping.
4. Add ATT&CK tags, a data source definition, and an analytic story reference.

Roughly speaking, conversion handles the detection logic and none of the operational scaffolding. That is worth stating plainly because "Sigma converts to Splunk" is often presented as a one-step process.

### Known conversion caveat

The pySigma Splunk backend does not parenthesise OR groups formed across separate selections. `a and (b or c)` emits as `fa="1" fb="2" OR fc="3"`, which SPL evaluates as `(a AND b) OR c` because AND binds tighter than OR. Any converted rule with that shape needs the parentheses added by hand before use. Reproduction and scope are documented in the Wireshark project.

---

## 2. Suricata EVE JSON from the IDS project

The [suricata-ids-rules](https://github.com/jesse12-21/suricata-ids-rules) project produces 23 engine-validated Suricata rules. Suricata writes alerts as EVE JSON, which ingests cleanly into Splunk.

### Ingest configuration

`inputs.conf` on the Suricata sensor:

```ini
[monitor:///var/log/suricata/eve.json]
disabled = false
index = ids_alerts
sourcetype = suricata:eve
```

`props.conf` on the indexer or heavy forwarder:

```ini
[suricata:eve]
INDEXED_EXTRACTIONS = json
KV_MODE = none
TIMESTAMP_FIELDS = timestamp
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%z
MAX_TIMESTAMP_LOOKAHEAD = 32
TRUNCATE = 0
SHOULD_LINEMERGE = false
```

`KV_MODE = none` is deliberate — with `INDEXED_EXTRACTIONS = json` already parsing the fields, leaving KV_MODE at its default causes Splunk to parse each event twice.

### Volume warning

EVE JSON logs **every** event type by default, not only alerts — flow, DNS, HTTP, TLS, and stats records included. On a busy sensor that is orders of magnitude more data than the alerts alone, and it is a genuinely expensive way to discover how Splunk licensing works. Restrict the output in `suricata.yaml` before pointing a forwarder at it:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: no
            metadata: yes
```

Add `http`, `dns`, and `tls` types only if you have a specific detection that needs them and have budgeted the volume.

### CIM normalisation

The [Splunk Add-on for Suricata](https://splunkbase.splunk.com/app/6113) maps EVE JSON to the `Intrusion_Detection` data model, which is what [`botsv1_high_severity_suricata_ids_alert.yml`](../detections/network/botsv1_high_severity_suricata_ids_alert.yml) searches.

One mapping to verify rather than assume: Suricata emits numeric severity 1–3 in EVE JSON, and the add-on maps these to the CIM severity vocabulary (`critical`, `high`, `medium`, `low`). The direction is inverted — Suricata severity 1 is the *most* severe. Confirm the mapping in your deployment before relying on a severity filter:

```
| tstats count from datamodel=Intrusion_Detection.IDS_Attacks by IDS_Attacks.severity
```

### Why IDS alerts are risk, not notables

A tuned Suricata sensor still produces far more alerts than a SOC can triage individually. Under alert-per-detection that forces a choice between ignoring the sensor and drowning in it.

As a risk source the volume becomes useful rather than harmful. An IDS alert on its own moves the needle slightly; an IDS alert against a host that also shows failed authentication and web scanning moves it decisively. This is why the detection scores 45 rather than raising a notable.

---

## 3. What this pipeline does not do

Stated so the architecture diagram is not read as a claim of more integration than exists:

- **Nothing is automated between the repositories.** Conversion and ingest are manual steps. A production pipeline would run Sigma conversion in CI and deploy the output; this does not.
- **Field names are not reconciled across sources.** Zeek uses `id.orig_h`, Suricata EVE uses `src_ip`, CIM uses `src`. The data models handle this where the add-ons are installed and do not where they are not.
- **The Wireshark Sigma rules are not present here as contentctl detections.** Converting all seven properly means writing seven RBA blocks and seven data source definitions, which is real work rather than a conversion step. The Suricata bridge is implemented; the Sigma bridge is documented.

That last point is the honest state of it. The mechanism is proven with one detection rather than claimed across seven.

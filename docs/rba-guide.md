# Risk-Based Alerting

Every detection in [`detections/`](../detections/) contributes **risk** to an entity rather than raising its own alert. This document explains why, how the scores were chosen, and what breaks if you get it wrong.

---

## The problem RBA solves

A conventional SIEM raises one notable per detection that fires. Add detections and alert volume rises linearly; tune thresholds up and you lose the low-and-slow activity that mattered. The queue fills with individually-defensible alerts that collectively tell an analyst nothing.

The failure is structural, not a tuning problem. Consider one source address that:

1. requests 200 URLs and gets 404 on all of them
2. sends a handful of requests containing `UNION SELECT`
3. produces 25 failed logons against a domain controller
4. authenticates successfully in the same hour

Under alert-per-detection that is four notables, probably assigned to different analysts, each closed as low severity in isolation. Scanning is background noise on any internet-facing host. Twenty-five failed logons is a forgotten service account. A successful logon is normal.

Together they are an intrusion, and no individual alert says so.

Risk-based alerting inverts the model. Each detection writes a scored risk event against an entity — a user or a system — and alerting happens when **accumulated** risk crosses a threshold. The four signals above become one entity with a risk score of 195 across four distinct detections and three ATT&CK techniques. That is a single investigation with the story already assembled.

Practitioners report alert-volume reductions between 50% and 90% after moving to this model.

---

## How it works in this repository

Every detection carries an `rba` block:

```yaml
rba:
  message: $src$ authenticated successfully as $user$ after $failures$ failed
    attempts within the same hour.
  risk_objects:
  - field: src
    type: system
    score: 70
  threat_objects: []
```

`contentctl build` turns that into the saved-search configuration Splunk ES consumes:

```
action.risk.param._risk = [{"risk_object_field": "src", "risk_object_type": "system", "risk_score": 70}]
```

The detection then writes to the Risk index instead of the notable index. Nothing appears in the analyst queue until a risk rule fires on the accumulated total.

**Risk objects** are the entity being scored — the thing under suspicion. **Threat objects** are supporting indicators that travel with the risk event but are not themselves scored: a URL, a file hash, an IDS signature. Getting this backwards is the most common RBA mistake. Scoring a URL means your "highest-risk entity" list fills with URLs instead of hosts.

---

## Scoring in this repository

| Detection | ATT&CK | Risk object | Score |
|---|---|---|---|
| Excessive Failed Logons From Single Source | T1110.001 | src (system) | 30 |
| | | user (user) | 20 |
| Successful Logon After Failed Logon Burst | T1110.001 | src (system) | 70 |
| Privileged Group Membership Change | T1098 | user (user) | 40 |
| Web SQL Injection Attempt | T1190 | src (system) | 60 |
| Web Scanning Via Not Found Responses | T1595.003 | src (system) | 35 |
| High Severity Suricata IDS Alert | T1595 | src (system) | 45 |

### Why these numbers

The scores are not arbitrary, and they are not a severity rating. A risk score answers one question: **how much does this observation move my belief that the entity is compromised?**

- **Low (30–40)** — behaviour that is common and usually benign. Failed logons and group membership changes happen constantly in a healthy environment. They belong in the model because they are *corroborating*, not because they are alarming.
- **Medium (45–60)** — behaviour with a narrower benign explanation. Injection patterns and high-severity IDS alerts are not routine, but both have real false-positive sources.
- **High (70)** — behaviour that is difficult to explain benignly. A successful authentication immediately following a failure burst is the pattern credential stuffing produces when it works.

Nothing scores above 70. That is deliberate. A single detection scoring 90+ effectively recreates alert-per-detection, because one firing crosses any sensible threshold on its own. If a detection genuinely warrants immediate response regardless of context, it should be a notable, not a risk contribution — the honest thing is to say so rather than to inflate a score.

### Two rules worth internalising

**Scores compose; think about the sums.** Two low-scoring detections against one entity should reach a level you would want to look at. 30 + 35 = 65 — noticeable, not urgent. Correct.

**Common behaviour gets low scores even when it is a real technique.** Group membership change is T1098, a genuine persistence technique, and it scores 40 because IT administration does it daily. The score reflects evidential weight in *your* environment, not the technique's severity in the abstract.

---

## Setting the alerting threshold

The threshold belongs to the environment, not the content. A starting method:

1. Deploy the detections in risk-only mode for two weeks.
2. Plot the distribution of accumulated per-entity risk over rolling 24-hour windows.
3. Set the initial threshold at roughly the 99th percentile.
4. Add a **distinct detection count** condition alongside the score.

Step 4 matters more than the number. An entity at 200 risk from one noisy detection firing forty times is a tuning problem. An entity at 120 from four different detections is an intrusion. The query:

```
| from datamodel Risk.All_Risk
| stats sum(All_Risk.calculated_risk_score) as total_risk,
        dc(All_Risk.search_name) as distinct_detections
  by All_Risk.risk_object
| where total_risk > 100 AND distinct_detections >= 3
```

ES 8.4 and later formalise this as **finding-based detections**, grouping individual risk events into one summarised finding that carries the whole story rather than fragments.

---

## Failure modes

**Score inflation.** Every detection author believes their detection is important. Left unchecked, everything scores 80 and the model degenerates back to alert-per-detection. Scores should be reviewed as a set, not per detection.

**Scoring the wrong object.** See threat objects above. If your top-risk list contains URLs, hashes, or signatures, the risk objects are wrong.

**Unbounded accumulation.** Risk that never decays means every long-lived server eventually crosses the threshold. ES applies a time window; verify yours is set.

**Noisy detections poisoning the model.** In alert-per-detection a noisy rule produces ignorable alerts. In RBA it silently inflates entity scores and pushes real signal below the threshold. **A noisy detection is more damaging under RBA, not less** — tune before enabling, and use ES finding exclusion rules for the remainder.

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Splunk Enterprise Security documentation](https://help.splunk.com/en/splunk-enterprise-security-8)
- [`docs/known-limitations.md`](known-limitations.md) — what this content does not cover
- [`docs/integrations.md`](integrations.md) — how the companion projects feed this one

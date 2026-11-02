# Underwriting use of the cyber scan

**Status: remediation step 1 of 6. No code change. Effective on issue to underwriting staff.**

Issued 8 September 2026, in response to the Cyber Resilience Africa capability
assessment of 16 August 2026 and the internal measurement that followed it.

---

## The rule

**A scan finding may load a rate or refer a risk to an analyst. The absence of
findings may never discount a rate, clear a referral, or grant a credit.**

The scan is a one-directional instrument. It can raise a concern; it cannot
retire one.

---

## Why this rule, and why it comes first

The external review identified that the scanner assesses the hostname submitted
rather than the client's estate. Measurement against 58 completed scans
established the frequency the review did not: the content delivery network
detector named a provider in **0 of 58** scans, and **14 of 58** resolved to a
provider edge range it did not recognise.

The consequence is specific. On a target fronted by a content delivery network,
the scanner assesses the provider's edge rather than the client's own servers,
finds it clean because the provider is well run, and reports a low score at full
confidence. boston.ac.za returned **97 out of 1000, Low risk, 100 percent
completeness, no failed checkers**, having assessed Cloudflare.

The two error directions are not symmetric, and the asymmetry is the reason for
the rule:

- **Overstatement is self-correcting.** A client challenges a loading, the
  finding is examined, and the error surfaces.
- **Understatement is silent.** Nobody disputes a clean report. A missed
  exposure is discovered when a claim arrives.

Under this rule the false-clean case stops mattering commercially. A scan that
sees nothing buys the insured nothing, so an estate the scanner failed to
discover cannot produce a cheaper price.

The rule also makes the remediation itself safe to ship. Three of the six
remediation steps move scores **downward**, because the scanner currently
penalises conditions it is about to start detecting correctly. Correcting the
network detector, for example, removes a business-interruption penalty that
every scan in the history has been carrying. Without this rule, the immediate
commercial effect of fixing an accuracy defect would be that affected clients
are rated more cheaply.

---

## What this means in practice

| Use of the scan | Permitted |
|---|---|
| Loading a rate on a finding | Yes |
| Referring a risk to an analyst on a finding | Yes |
| Triggering an exclusion or a condition on a finding | Yes |
| Prioritising remediation discussion with the client | Yes |
| Discounting a rate because the scan found little | **No** |
| Clearing an existing referral because a later scan is clean | **No** |
| Granting a schedule credit for a low score | **No** |
| Declining solely on a scan finding, without analyst review | **No** |

A clean scan is recorded as **not evidencing exposure**, never as evidencing its
absence. That is the same distinction the reports already draw between a check
that ran and a check that could not run.

---

## Mandatory analyst check

Until remediation step 3 ships, any scan of a target that is fronted by a
content delivery network, or hosted on shared infrastructure, carries an analyst
attribution check before the result is used at all. The scan report does not yet
state which case applies, so the check is manual: confirm that the addresses
assessed belong to the client.

Step 3 adds an estate-confidence measure to the report and this manual check is
withdrawn when it lands.

---

## What the scan remains good for

Nothing here reduces the value of the instrument. The scan finds real exposure,
it is the only external view available before binding, and its credential,
breach and compliance findings are unaffected by the attribution defect. The
rule constrains one thing only: the direction in which a scan result is allowed
to move a price.

---

## Review

This rule is reviewed when remediation steps 3 and 5 have landed and the
validation in step 6 has been published. The reasonable outcome at that point is
that the rule is relaxed for targets whose estate confidence the scanner can
itself vouch for, and retained for those where it cannot.

Related: `OUTSTANDING.md` sections 4b and 5, and the remediation plan issued with
the review response.

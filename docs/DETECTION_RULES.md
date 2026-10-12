# SentinelLog — Detection Rule Catalog & Correlation Guide

**Document Version:** 1.0.0  
**Application Version:** 2.4.0  

---

## 1. Rule Catalog

### RULE-AUTH-001: Repeated Failed Login Attempts
- **Target Indicator:** Multiple unsuccessful authentication attempts originating from a single source address within a bounded rolling time window.
- **Severity:** `HIGH`
- **Default Threshold:** 3 failed login occurrences within 5 minutes (`300 seconds`).
- **Detection Mechanism:**
  - Matches log records containing `"failed login"` (case-insensitive) and an extracted valid IPv4 address.
  - Computes rolling time spans across sorted timestamps.
  - Alert triggers on the exact threshold-reaching event timestamp.
- **Legacy Fallback:** If log records lack timestamps, triggers a legacy unverified alert if the cumulative failure count reaches the threshold across the entire file.
- **False Positive Considerations:**
  - User password typos or forgotten credentials.
  - Misconfigured automated scripts or scheduled tasks retrying bad credentials.

### RULE-AUTH-002: Unauthorized Access Attempt
- **Target Indicator:** Explicit unauthorized resource or endpoint access indicators recorded in application logs.
- **Severity:** `HIGH`
- **Detection Mechanism:**
  - Matches log records containing `"unauthorized access"` (case-insensitive).
  - Captures source IPv4, message context, and ISO timestamp.
- **False Positive Considerations:**
  - Expired session tokens or legitimate users clicking restricted administrative links without malice.

---

## 2. Incident Correlation Engine

### Concept: Alerts vs. Incidents
- **Alert:** An isolated symptom or rule hit (e.g., 3 failed logins or an unauthorized access indicator).
- **Incident:** An aggregated cluster of alerts sharing a common source entity within a bounded operational window.

### Correlation Criteria:
1. **Source Entity:** Shared, validated IPv4 address.
2. **Timestamps:** Valid, parseable ISO-8601 style timestamps (`%Y-%m-%d %H:%M:%S`).
3. **Correlation Window:** 5 minutes default (`window_minutes = 5`).
4. **Anti-Chaining Invariant:**
   $$\text{last\_seen} - \text{first\_seen} \le \text{window\_minutes}$$
   Events at $10:00$, $10:04$, and $10:07$ will form two distinct incidents ($[10:00, 10:04]$ and $[10:07]$), preventing transitive chaining from artificially bridging hours of separate activity.

### Severity Hierarchy:
$$\text{CRITICAL} > \text{HIGH} > \text{MEDIUM} > \text{LOW} > \text{INFO}$$
The incident severity is dynamically assigned to the maximum severity among all linked alerts.

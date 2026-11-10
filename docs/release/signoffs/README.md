# Operator sign-offs for the release gate

`tools/release-gate/check.py` treats an item with `signoff:<name>` as BLOCKED until
`docs/release/signoffs/<name>.md` exists with BOTH lines below. Only the operator writes these files — an
agent never creates or edits a sign-off.

```
Approved-by: <operator name>
Date: <YYYY-MM-DD>
Decision: <what was decided, e.g. "OTP provisioned on the factory station for batch 1" or "SEC-3 out of scope for release 1.0">
Evidence: <link to the provisioning log / ceremony record / certificate>
```

Pending sign-offs: key-custody, otp-provisioning, sec3-secure-boot, rpmb, certification, firmware-licence.
Decision records: `docs/design/heqk-decision-record-otp-rpmb-2026-11-10.md`.

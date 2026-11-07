# onboarding/ — first boot and registration

How a new device goes from power-on to protecting a network. Enrollment is **optional**. With no
account, the device runs a full local SOC, air-gapped (standalone by default).

| Step | Folder |
|---|---|
| 1. Bring up Wi-Fi (heqk as a WPA2 access point, or as a client) | [`wifi/`](wifi/) |
| 2. Sign in to Mission Control with the device's owner key | [`setup-ui/`](setup-ui/) |
| 3. Optional: enroll with a control plane (MSSP or self-hosted) | [`enrollment/`](enrollment/) |

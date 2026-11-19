# SPDX-License-Identifier: AGPL-3.0-only
"""The licence gate. One function decides whether a source's data may be used for a purpose, from the
licence registry alone. 'unclear' and 'requires_agreement' count as NO until an agreement is recorded
by changing the registry entry (a reviewed commit).

Purposes:
  commercial_training  weights that ship in, or are sold with, HookProbe OS (the dual-licence model
                       makes every model we train a commercial artefact)
  evaluation           benchmarking a commercial model internally (still commercial use)
  research             non-commercial research reports only; nothing derived may enter a shipped model
  live_intel           shipping the indicators themselves on devices (redistribution)
"""
PURPOSES = ("commercial_training", "evaluation", "research", "live_intel")


class LicenseDenied(Exception):
    pass


def decide(lic, purpose):
    """(allowed: bool, reason: str) for licence registry entry `lic` and `purpose`."""
    if purpose not in PURPOSES:
        raise ValueError(f"unknown purpose {purpose!r}")
    cls = lic["class"]
    if cls == "UNKNOWN":
        return False, f"licence {lic['id']} is UNKNOWN (not verified)"
    if cls == "RESTRICTED":
        return False, f"licence {lic['id']} is RESTRICTED (needs a recorded agreement)"
    if purpose == "research":
        if lic["training_use"] == "no":
            return False, f"licence {lic['id']} forbids training/derivative analysis"
        return True, f"{cls} licence permits research use"
    if lic["commercial_use"] != "yes":
        return False, f"licence {lic['id']} commercial_use={lic['commercial_use']}"
    if purpose == "live_intel":
        if lic["redistribution"] != "yes":
            return False, f"licence {lic['id']} redistribution={lic['redistribution']}"
        return True, "commercial redistribution permitted"
    if purpose == "commercial_training":
        if lic["training_use"] != "yes":
            return False, f"licence {lic['id']} training_use={lic['training_use']}"
        if lic["share_alike"]:
            return False, f"licence {lic['id']} is share-alike: whether model weights are an adaptation is unresolved; needs legal review"
        return True, "commercial training permitted"
    # evaluation
    if lic["training_use"] == "no" and lic["derivatives"] == "no":
        return False, f"licence {lic['id']} forbids derivative use"
    return True, "commercial evaluation permitted"


def require(lic, purpose):
    ok, why = decide(lic, purpose)
    if not ok:
        raise LicenseDenied(why)
    return why

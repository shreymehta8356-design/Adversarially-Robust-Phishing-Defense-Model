"""The attack taxonomy and the capability model it rests on.

"Threat-informed" means the attacks tested here are bounded by what an attacker
can actually do, not by what is convenient to implement. Getting that boundary
right is the difference between a robustness number that means something and
one that is either trivially pessimistic (assume the attacker can do anything,
so nothing works) or trivially optimistic (assume they can only add typos).

Capability model
----------------
The adversary is a **competent phishing operator with full knowledge of the
message they send and black-box query access to the detector's verdict**. That
is the realistic worst case: commercial phishing kits are routinely tested
against public scanners before a campaign launches.

They CAN:
  * rewrite any part of the message they author - subject, body, HTML, display
    name, Reply-To, attachment names;
  * choose their own infrastructure - domain, host, path, redirect chains,
    shortener wrapping, punycode registration;
  * choose *when* and *how fast* to send - time of day, pacing, recipient count,
    whether the subject is framed as a reply;
  * observe the detector's score for a candidate message and iterate, up to a
    query budget.

They CANNOT:
  * change the recipient's history with them - prior correspondence volume and
    reply ratio are properties of the victim's mailbox, not of the message;
  * age their own domain retroactively, or erase user reports already filed
    against it;
  * make the brand's genuine domain send the mail - taking over
    ``paypal.com`` is domain compromise, a different threat with different
    controls, explicitly out of scope and recorded as such in the threat model;
  * see model weights or gradients - this is a black-box, decision-based threat
    model, not a white-box one.

Those boundaries are enforced mechanically: the behavioral transforms in
:mod:`phishguard.adversarial.transforms` mutate only the attacker-controlled
fields, and :func:`phishguard.adversarial.transforms.payload_preserved` rejects
any candidate that stops being a working phishing message.

Families
--------
Six, chosen so that each maps to a distinct defensive control and can be scored
independently in the residual-risk register.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class AttackFamily:
    """One branch of the taxonomy."""

    id: str
    name: str
    description: str
    capability: str
    #: Defensive control IDs intended to blunt this family.
    countered_by: tuple[str, ...]
    #: Qualitative cost to the attacker of using this family.
    attacker_cost: str
    #: Does using this family degrade the lure for the victim?
    victim_visible: str


ATTACK_FAMILIES: tuple[AttackFamily, ...] = (
    AttackFamily(
        id="A-LEX",
        name="Lexical and semantic perturbation",
        description=(
            "Rewriting the message text while preserving its meaning: synonym "
            "substitution over the pressure and credential vocabulary, character-level "
            "typos, benign padding drawn from legitimate mail, removal of shouted "
            "capitals and exclamation marks, and softening of overt threats."
        ),
        capability="Free - the attacker authors the text",
        countered_by=("D-NORM", "D-ADVTRAIN", "D-ENSEMBLE", "D-ABSTAIN"),
        attacker_cost="Low",
        victim_visible="No - the lure reads normally, often better",
    ),
    AttackFamily(
        id="A-UNI",
        name="Unicode and homoglyph obfuscation",
        description=(
            "Substituting visually identical characters from other scripts, inserting "
            "zero-width joiners inside trigger words, adding combining diacritics, "
            "leetspeak substitution and intra-word separators."
        ),
        capability="Free - any mail client renders these identically",
        countered_by=("D-NORM", "D-ADVTRAIN"),
        attacker_cost="Low",
        victim_visible="Barely - rendering is near-identical",
    ),
    AttackFamily(
        id="A-URL",
        name="URL obfuscation and redirection",
        description=(
            "Hiding the destination: shortener wrapping, open-redirect chaining through "
            "a neutral host, percent-encoding, subdomain padding, bare-IP hosts, "
            "punycode registration and path-token noise."
        ),
        capability="Cheap - requires only a redirect host or a shortener account",
        countered_by=("D-URL", "D-ADVTRAIN", "D-ENSEMBLE"),
        attacker_cost="Low to medium",
        victim_visible="Yes if the victim inspects the link before clicking",
    ),
    AttackFamily(
        id="A-STRUCT",
        name="Structural and HTML manipulation",
        description=(
            "Moving the lure out of the plain-text channel: HTML entity encoding, "
            "invisible spans splitting trigger words, replacing body text with an image "
            "reference, and tag noise that inflates the markup-to-text ratio."
        ),
        capability="Free - the attacker authors the HTML part",
        countered_by=("D-NORM", "D-ENSEMBLE", "D-ADVTRAIN"),
        attacker_cost="Low",
        victim_visible="No",
    ),
    AttackFamily(
        id="A-HDR",
        name="Header and identity shaping",
        description=(
            "Making the envelope look consistent: dropping a divergent Reply-To, "
            "removing brand claims from the display name so no mismatch is detectable, "
            "publishing correct SPF/DKIM records for the attacker's own throwaway "
            "domain, and reducing the visible hop count."
        ),
        capability=(
            "Cheap for the attacker's own domain; impossible for the brand's real "
            "domain, which is domain compromise and out of scope"
        ),
        countered_by=("D-ENSEMBLE", "D-ABSTAIN"),
        attacker_cost="Medium",
        victim_visible="No - improves the lure's credibility",
    ),
    AttackFamily(
        id="A-BEH",
        name="Behavioral and timing mimicry",
        description=(
            "Sending like a legitimate correspondent: business-hours delivery, "
            "low-and-slow pacing instead of a burst, single-recipient targeting and "
            "reply-framed subjects that imply an existing thread."
        ),
        capability=(
            "Attacker controls send time, pacing and framing; cannot fabricate the "
            "recipient's prior correspondence history or the age of their own domain"
        ),
        countered_by=("D-VELOCITY", "D-ENSEMBLE", "D-ABSTAIN"),
        attacker_cost="High - low-and-slow sending cuts campaign reach",
        victim_visible="No",
    ),
)

FAMILY_BY_ID: dict[str, AttackFamily] = {f.id: f for f in ATTACK_FAMILIES}


def describe_taxonomy() -> list[dict[str, Any]]:
    """Rows for the threat model, the model card and ``GET /api/v1/model``."""
    return [
        {
            "id": f.id,
            "name": f.name,
            "description": f.description,
            "capability": f.capability,
            "countered_by": list(f.countered_by),
            "attacker_cost": f.attacker_cost,
            "victim_visible": f.victim_visible,
        }
        for f in ATTACK_FAMILIES
    ]


#: Explicitly out of scope, recorded so the residual-risk register is honest
#: about what this system does *not* defend against.
OUT_OF_SCOPE: tuple[dict[str, str], ...] = (
    {
        "id": "OOS-1",
        "threat": "Compromise of a genuine brand or partner domain",
        "why": (
            "Mail genuinely originating from the real domain passes every header and "
            "reputation check by construction. This is an authentication and account-"
            "security problem, not a content-classification one."
        ),
        "mitigation_elsewhere": "MFA on mail accounts, DMARC enforcement, egress monitoring",
    },
    {
        "id": "OOS-2",
        "threat": "White-box gradient-based evasion",
        "why": (
            "Assumes the attacker holds model weights. If weights leak, the correct "
            "response is rotation and retraining, not a robustness claim."
        ),
        "mitigation_elsewhere": "Artefact access control, model registry auditing",
    },
    {
        "id": "OOS-3",
        "threat": "Training-data poisoning through the analyst feedback loop",
        "why": (
            "Feedback is stored and surfaced for review but is never used to retrain "
            "automatically. Retraining is a deliberate, reviewed action."
        ),
        "mitigation_elsewhere": "Human review of feedback before any retraining run",
    },
    {
        "id": "OOS-4",
        "threat": "Malicious payload analysis (attachment detonation, page fetching)",
        "why": (
            "The system deliberately never resolves a URL or opens an attachment. "
            "Fetching attacker-controlled content from the gateway would create an SSRF "
            "surface and leak victim telemetry to the attacker."
        ),
        "mitigation_elsewhere": "A dedicated sandbox detonation service downstream",
    },
)

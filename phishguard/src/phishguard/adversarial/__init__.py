"""Threat-informed adversarial testing.

``taxonomy``    the six attack families and the capability model behind them
``transforms``  semantic-preserving perturbations, one per taxonomy entry
``attacker``    budgeted search over transforms with validity constraints
``report``      attack-success rate, robustness drop and the residual-risk register
"""

from phishguard.adversarial.attacker import (
    AttackResult,
    BudgetedAttacker,
    RawScoreSurface,
    single_transform_sweep,
)
from phishguard.adversarial.taxonomy import (
    ATTACK_FAMILIES,
    AttackFamily,
    describe_taxonomy,
)
from phishguard.adversarial.transforms import (
    TRANSFORMS,
    apply_transform,
    random_perturbation,
)

__all__ = [
    "ATTACK_FAMILIES",
    "AttackFamily",
    "AttackResult",
    "BudgetedAttacker",
    "RawScoreSurface",
    "TRANSFORMS",
    "apply_transform",
    "describe_taxonomy",
    "random_perturbation",
    "single_transform_sweep",
]

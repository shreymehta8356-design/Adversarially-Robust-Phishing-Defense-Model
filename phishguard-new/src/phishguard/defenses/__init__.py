"""Defensive controls that can be individually enabled, disabled and ablated."""

from phishguard.defenses.controls import (
    DEFENSE_IDS,
    DefenseConfig,
    describe_defenses,
)

__all__ = ["DEFENSE_IDS", "DefenseConfig", "describe_defenses"]

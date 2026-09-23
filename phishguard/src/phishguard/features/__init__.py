"""The three feature families and the assembler that joins them.

Each family is independently importable, independently testable and can be
switched off for the modality-ablation study:

* :mod:`phishguard.features.urls`        - lexical / structural URL signals
* :mod:`phishguard.features.email`       - header, subject, body and HTML signals
* :mod:`phishguard.features.behavioral`  - sender-relationship and timing signals
* :mod:`phishguard.features.assembler`   - joins them into a stable vector
"""

from phishguard.features.assembler import (
    FEATURE_FAMILIES,
    FeatureAssembler,
    FeatureVector,
)

__all__ = ["FEATURE_FAMILIES", "FeatureAssembler", "FeatureVector"]

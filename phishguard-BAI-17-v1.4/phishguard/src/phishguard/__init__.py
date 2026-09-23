"""PhishGuard - Adversarially Robust Phishing Defense.

An end-to-end phishing detection system that fuses email, URL and behavioral
signals, and is explicitly engineered, measured and hardened against an
attacker who is allowed to rewrite the message.

Package layout
--------------
``features``     three independent feature families (email / url / behavioral)
``data``         synthetic corpus generator, public-corpus loaders, leakage-safe splits
``models``       rule baseline, classical models, calibrated fusion, registry
``adversarial``  attack taxonomy, semantic-preserving transforms, budgeted attacker
``defenses``     normalization, adversarial training, abstention, ablation harness
``explain``      exact contribution attribution and analyst evidence cards
``eval``         metrics, error analysis, acceptance gates
``service``      FastAPI adapter over a dependency-free core
"""

__version__ = "1.4.0"
__all__ = ["__version__"]

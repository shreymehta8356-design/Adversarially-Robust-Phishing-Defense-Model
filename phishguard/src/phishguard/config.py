"""Central configuration.

Every tunable lives here so that experiments are reproducible from a single
declared state. Values are overridable by environment variable (prefix
``PG_``) or a ``.env`` file; secrets are never given usable defaults.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
PACKAGE_ROOT = Path(__file__).resolve().parent


def _find_project_root() -> Path:
    """Locate the repository root, or fall back to the working directory.

    ``PACKAGE_ROOT.parents[1]`` is the repository root **only** in a source
    checkout (``<repo>/src/phishguard``). After ``pip install`` the package
    lives in ``site-packages``, where the same expression resolves to something
    like ``/usr/lib/python3.11`` -- and using that as the artifacts directory
    means ``phishguard train`` tries to write a model registry into a system
    directory. It fails with a permission error on Linux and macOS, and
    silently pollutes the interpreter's install on Windows.

    So the root is confirmed by looking for a marker file, and anything else
    falls back to the current working directory, which is what a user running
    ``phishguard train`` in their own folder expects.
    """
    for candidate in PACKAGE_ROOT.parents:
        if (candidate / "pyproject.toml").exists() and (candidate / "src").is_dir():
            return candidate
    return Path.cwd()


PROJECT_ROOT = _find_project_root()


def _default_artifacts() -> Path:
    return Path(os.environ.get("PG_ARTIFACTS_DIR", PROJECT_ROOT / "artifacts"))


def find_console_asset() -> Path | None:
    """Locate the analyst console HTML across every install layout.

    Shipped as package data, so the first candidate is the normal answer. The
    remaining candidates keep a source checkout, an editable install and a
    container with a bind-mounted copy all working.
    """
    candidates: list[Path] = []
    env_override = os.environ.get("PG_UI_PATH", "").strip()
    if env_override:
        candidates.append(Path(env_override))
    candidates += [
        PACKAGE_ROOT / "static" / "index.html",       # packaged (normal case)
        PROJECT_ROOT / "src" / "phishguard" / "static" / "index.html",
        PROJECT_ROOT / "ui" / "index.html",           # legacy source layout
        Path("/app/ui/index.html"),                   # container bind mount
        Path.cwd() / "ui" / "index.html",
    ]
    for path in candidates:
        try:
            if path.is_file():
                return path
        except OSError:  # unreadable or a malformed path on this platform
            continue
    return None


class Settings(BaseSettings):
    """Runtime settings for training and serving."""

    model_config = SettingsConfigDict(
        env_prefix="PG_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        protected_namespaces=(),
    )

    # ---------------------------------------------------------------- general
    environment: Literal["dev", "test", "prod"] = "dev"
    log_level: str = "INFO"
    log_format: Literal["json", "text"] = "json"
    random_seed: int = 20260907

    artifacts_dir: Path = Field(default_factory=_default_artifacts)
    model_dir: Path | None = None
    data_dir: Path | None = None

    # ------------------------------------------------------------------ data
    synthetic_n_train: int = 9000
    synthetic_n_test: int = 3000
    synthetic_phish_ratio: float = 0.42
    #: Fraction of the training pool reserved for probability calibration.
    calibration_fraction: float = 0.2
    #: Jaccard threshold above which two messages count as near-duplicates.
    near_duplicate_threshold: float = 0.85

    # ----------------------------------------------------------------- model
    #: Which members take part in the fusion. Order is stable and meaningful.
    enabled_members: tuple[str, ...] = ("rules", "engineered", "charngram", "wordtfidf")
    use_transformer: bool = False
    transformer_name: str = "distilbert-base-uncased"
    transformer_epochs: int = 2
    transformer_max_len: int = 256

    #: Adversarially augmented copies added per phishing training example.
    adv_train_multiplier: int = 1
    adv_train_enabled: bool = True

    # ------------------------------------------------- decision bands (0..1)
    #: p < review_threshold          -> ALLOW
    #: review_threshold <= p < block -> REVIEW  (human in the loop)
    #: p >= block_threshold          -> BLOCK
    review_threshold: float = 0.40
    block_threshold: float = 0.80

    # ------------------------------------------------------------ adversarial
    attack_budget: int = 10
    attack_max_candidates_per_step: int = 24
    attack_seed: int = 7

    # ------------------------------------------------------- acceptance gates
    gate_macro_f1: float = 0.90
    gate_pr_auc: float = 0.93
    gate_max_fpr: float = 0.02
    gate_max_ece: float = 0.08
    gate_max_robustness_drop: float = 0.15
    gate_max_attack_success_rate: float = 0.35
    gate_p95_latency_ms: float = 150.0

    # --------------------------------------------------------------- service
    api_host: str = "0.0.0.0"  # noqa: S104 - container binds all interfaces by design
    api_port: int = 8000
    api_root_path: str = ""
    cors_origins: tuple[str, ...] = ("http://localhost:8000", "http://127.0.0.1:8000")

    #: ``role:key`` pairs, comma separated. Never commit real keys.
    api_keys: str = ""
    #: Used only when ``api_keys`` is empty AND environment == dev.
    dev_analyst_key: str = "dev-analyst-key-change-me"
    dev_admin_key: str = "dev-admin-key-change-me"

    rate_limit_per_minute: int = 120
    max_body_bytes: int = 1_000_000
    max_urls_per_email: int = 200
    request_timeout_s: float = 10.0

    database_url: str = ""
    audit_retention_days: int = 90
    #: Salt for hashing identifiers written to the audit log. Override in prod.
    pseudonymization_salt: str = "phishguard-dev-salt"

    @field_validator("artifacts_dir", mode="after")
    @classmethod
    def _abs_artifacts(cls, v: Path) -> Path:
        return v if v.is_absolute() else (PROJECT_ROOT / v).resolve()

    @property
    def models_path(self) -> Path:
        return self.model_dir or (self.artifacts_dir / "models")

    @property
    def data_path(self) -> Path:
        return self.data_dir or (self.artifacts_dir / "data")

    @property
    def reports_path(self) -> Path:
        return self.artifacts_dir / "reports"

    @property
    def db_path(self) -> Path:
        if self.database_url:
            return Path(self.database_url)
        return self.artifacts_dir / "phishguard.db"

    def ensure_dirs(self) -> None:
        for p in (self.artifacts_dir, self.models_path, self.data_path, self.reports_path):
            p.mkdir(parents=True, exist_ok=True)

    def resolved_api_keys(self) -> dict[str, str]:
        """Return ``{api_key: role}``.

        Production must supply ``PG_API_KEYS``. Development falls back to two
        obvious placeholder keys so a fresh clone is usable in one command --
        and the service logs a loud warning when it does.
        """
        mapping: dict[str, str] = {}
        raw = self.api_keys.strip()
        if raw:
            for pair in raw.split(","):
                pair = pair.strip()
                if not pair or ":" not in pair:
                    continue
                role, _, key = pair.partition(":")
                role, key = role.strip().lower(), key.strip()
                if role in {"analyst", "admin"} and key:
                    mapping[key] = role
        elif self.environment != "prod":
            mapping[self.dev_analyst_key] = "analyst"
            mapping[self.dev_admin_key] = "admin"
        return mapping


_settings: Settings | None = None


def get_settings(refresh: bool = False) -> Settings:
    """Process-wide settings singleton."""
    global _settings
    if _settings is None or refresh:
        _settings = Settings()
    return _settings

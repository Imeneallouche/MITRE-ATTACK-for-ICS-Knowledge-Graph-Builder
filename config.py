"""
Configuration for the MITRE ATT&CK for ICS Knowledge Graph tools.

Secrets (Neo4j password, etc.) must be supplied via the environment or a ``.env``
file in the repository root. Never commit ``.env``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

REPO_ROOT: Path = Path(__file__).resolve().parent


class ConfigurationError(RuntimeError):
    """Raised when required configuration is missing."""


def load_environment(override: bool = False) -> None:
    """Load ``.env`` from the repository root if present."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    path = REPO_ROOT / ".env"
    if path.is_file():
        load_dotenv(path, override=override)


def _strip(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _first_non_empty(*names: str) -> Optional[str]:
    for name in names:
        v = _strip(os.environ.get(name))
        if v is not None:
            return v
    return None


def get_neo4j_credentials() -> Tuple[str, str, str]:
    """
    Return (uri, user, password).

    Required: NEO4J_URI, NEO4J_PASSWORD, and NEO4J_USER or NEO4J_USERNAME.
    """
    load_environment()
    uri = _first_non_empty("NEO4J_URI")
    user = _first_non_empty("NEO4J_USER", "NEO4J_USERNAME")
    password = _first_non_empty("NEO4J_PASSWORD")
    missing: list[str] = []
    if not uri:
        missing.append("NEO4J_URI")
    if not user:
        missing.append("NEO4J_USER (or NEO4J_USERNAME)")
    if not password:
        missing.append("NEO4J_PASSWORD")
    if missing:
        raise ConfigurationError(
            "Missing Neo4j configuration: "
            + ", ".join(missing)
            + ". Set variables in the environment or in .env (see .env.example)."
        )
    return uri, user, password


def safe_log_neo4j_target(uri: str) -> str:
    """Log scheme and host only (not credentials)."""
    try:
        p = urlparse(uri)
        if p.netloc:
            return f"{p.scheme}://{p.netloc}" if p.scheme else p.netloc
    except Exception:
        pass
    return "(configured)"


def resolve_repo_path(env_name: str, default_relative: str) -> Path:
    """
    Read optional env var ``env_name``; if unset, use ``REPO_ROOT / default_relative``.
    """
    load_environment()
    raw = _strip(os.environ.get(env_name)) or default_relative
    p = Path(raw)
    if p.is_absolute():
        return p
    return (REPO_ROOT / p).resolve()


def get_clear_database_default() -> bool:
    """MITRE_KG_CLEAR_EXISTING: default true. Set to 'false' to append (v18 only)."""
    load_environment()
    v = _strip(os.environ.get("MITRE_KG_CLEAR_EXISTING", "true")) or "true"
    return v.lower() in ("1", "true", "yes", "y", "on")


def path_v18_matrix_excel() -> Path:
    """Main ATT&CK for ICS v18 Excel for ``mitre_ics_matrix_v18_to_kg.py``."""
    return resolve_repo_path("MITRE_ICS_V18_EXCEL", "input/ics-attack-v18.0.xlsx")


def path_v17_matrix_excel() -> Path:
    """ATT&CK for ICS v17 Excel for ``mitre_ics_matrix_v17_to_kg.py``."""
    return resolve_repo_path("MITRE_ICS_V17_EXCEL", "input/ics-attack-v17.1.xlsx")


def path_v18_complementary_excel() -> Path:
    """Complementary workbook for ``add_missing_relationships.py``."""
    return resolve_repo_path(
        "MITRE_ICS_V18_COMPLEMENTARY_EXCEL",
        "input/ics-attack-v18.0-complementary.xlsx",
    )


def path_datacomponent_scraper_input() -> Path:
    return resolve_repo_path(
        "MITRE_DATACOMPONENT_SCRAPER_INPUT",
        "input/ics-attack-v18.0.xlsx",
    )


def path_datacomponent_scraper_output() -> Path:
    return resolve_repo_path(
        "MITRE_DATACOMPONENT_SCRAPER_OUTPUT",
        "analytics_with_datacomponents.xlsx",
    )


def path_detection_strategy_mapping_input() -> Path:
    return resolve_repo_path(
        "MITRE_DS_ANALYTIC_MAP_INPUT",
        "input/ics-attack-v18.0.xlsx",
    )


def path_detection_strategy_mapping_output() -> Path:
    return resolve_repo_path(
        "MITRE_DS_ANALYTIC_MAP_OUTPUT",
        "analytic_detectionstrategy_mapping.xlsx",
    )

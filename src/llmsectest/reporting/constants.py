"""Shared constants for the llmsectest reporting layer.

Centralizes severity mappings, colors, and emojis to avoid duplication
across report generators.
"""

# Severity level ordering (highest to lowest)
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# SARIF severity level mapping
SARIF_SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none"
}

# Numeric severity scores for security tools (CVSS-like)
SEVERITY_SCORES = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "0.0",
}

# Emoji indicators for terminal/markdown output
SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪"
}

# HTML hex colors for reports
SEVERITY_COLORS_HEX = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#17a2b8",
    "info": "#6c757d"
}

# Badge colors for markdown
SEVERITY_BADGE_COLORS = {
    "critical": "red",
    "high": "orange",
    "medium": "yellow",
    "low": "blue",
    "info": "lightgrey"
}

# Risk level emoji mapping
RISK_LEVEL_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "minimal": "✅"
}

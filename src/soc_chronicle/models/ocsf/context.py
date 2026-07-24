"""Normalization context for parser-level configuration."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class NormalizationContext:
    """Per-investigation or per-host normalization settings.

    Parameters
    ----------
    default_skew_offset_seconds:
        Global clock-skew correction applied to all timestamps when a
        per-host offset is not configured.
    host_skew_offsets:
        Mapping of hostname → skew offset in seconds. Use when specific
        hosts are known to have clock drift (e.g., ``{"FIN-23": -30}``).
    source_type:
        Default ``source_type`` label applied when a parser does not set one.
    strict_mode:
        When ``True``, events missing mandatory fields (``timestamp``,
        ``class_uid``, ``activity_name``) are dropped rather than filled
        with defaults.
    """

    default_skew_offset_seconds: float = 0.0
    host_skew_offsets: dict[str, float] = field(default_factory=dict)
    source_type: str = "unknown"
    strict_mode: bool = False

    def skew_for_host(self, host: str | None) -> float:
        """Return the clock-skew offset for a given host."""
        if host and host in self.host_skew_offsets:
            return self.host_skew_offsets[host]
        return self.default_skew_offset_seconds

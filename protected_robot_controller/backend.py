"""Trusted construction-time backend contract. Never exposed to a message peer."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Observation:
    counter: int
    physics_step: int
    simulation_time_ns: int
    monotonic_time_ns: int
    positions: tuple[float, ...]  # Six radians, then two metres.
    valid: tuple[bool, ...]


class PrivateBackend(Protocol):
    def read_initial(self) -> Observation:
        """Fresh private acquisition at the current settled physics state."""
        ...

    def drive(self, targets: tuple[float, ...], *, velocity_limits: tuple[float, ...],
              effort_limits: tuple[float, ...]) -> None:
        """Write seven targets through locally capped drives, never sensor state."""
        ...

    def step_physics(self, *, deadline_ns: int) -> None:
        """Advance one 1/120 s step; enforce the deadline inside the adapter too."""
        ...

    def sample_outputs(self) -> Observation:
        """Copy all eight actual outputs after that step; no target-derived data."""
        ...

    def stop_or_hold(self, reason: str) -> None:
        """Request a bounded hold using protected configuration, even on faults."""
        ...

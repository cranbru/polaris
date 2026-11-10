"""Presentation-independent progress and cooperative cancellation.

Percentages count completed units inside weighted stages. Unknown work emits
an indeterminate event. 100% means the workflow finished, including runs whose
saved diagnostics record collection or integrity gaps.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from threading import Event
from time import monotonic
from typing import Callable


class AcquisitionCancelled(Exception):
    """The examiner stopped the current acquisition."""


class CancellationToken:
    def __init__(self):
        self.event = Event()

    def cancel(self):
        self.event.set()

    def check(self):
        if self.event.is_set():
            raise AcquisitionCancelled("Acquisition cancelled. Captured evidence has been preserved.")


@dataclass(frozen=True)
class ProgressEvent:
    stage: str
    operation: str
    state: str
    completed: int = 0
    total: int | None = None
    percentage: float | None = None
    elapsed_seconds: float = 0
    eta_seconds: float | None = None
    module_id: str = ""
    error: str = ""
    detail: str = ""
    stages: tuple = ()
    workflow_completed: bool = False

    def to_dict(self):
        return asdict(self)


_token: ContextVar[CancellationToken | None] = ContextVar("polaris_cancellation", default=None)
_observer: ContextVar[Callable | None] = ContextVar("polaris_operation_observer", default=None)


def check_cancelled():
    token = _token.get()
    if token:
        token.check()


def observe_operation(operation: str, detail: str = ""):
    check_cancelled()
    observer = _observer.get()
    if observer:
        observer(operation, detail)


@contextmanager
def processing_context(token: CancellationToken, observer: Callable | None = None):
    token_handle = _token.set(token)
    observer_handle = _observer.set(observer)
    try:
        yield
    finally:
        _observer.reset(observer_handle)
        _token.reset(token_handle)


class ProgressTracker:
    def __init__(self, stages: list[tuple[str, str, int]], callback: Callable[[ProgressEvent], None]):
        self.stages = stages
        self.callback = callback
        self.done: set[str] = set()
        self.current = stages[0][0]
        self.started = monotonic()
        self.completed = 0
        self.total = None
        self.last_percentage = 0.0
        self.known_totals: dict[str, int] = {}
        self.terminal = False

    def update(self, stage: str, operation: str, completed: int = 0,
               total: int | None = None, detail: str = "", module_id: str = ""):
        if self.terminal:
            return
        if stage not in {s[0] for s in self.stages}:
            raise ValueError(f"Unknown progress stage: {stage}")
        self.current, self.completed, self.total = stage, completed, total
        weight_sum = sum(s[2] for s in self.stages)
        base = sum(s[2] for s in self.stages if s[0] in self.done)
        weight = 0 if stage in self.done else next(s[2] for s in self.stages if s[0] == stage)
        percentage = None
        if total is not None and total > 0:
            if not 0 <= completed <= total:
                raise ValueError("Completed work must be within the known workload.")
            percentage = min(99.9, (base + weight * completed / total) * 100 / weight_sum)
            self.last_percentage = max(self.last_percentage, percentage)
            percentage = self.last_percentage
            self.known_totals[stage] = total
        state = "RUNNING" if percentage is not None else "INITIALIZING" if stage == "initializing" else "INDETERMINATE"
        self._emit(operation, state,
                   percentage, detail=detail, module_id=module_id)

    def finish_stage(self, stage: str, operation: str):
        self.done.add(stage)
        total = self.known_totals.get(stage, 1)
        self.update(stage, operation, total, total)

    def finish(self, state: str, operation: str, error: str = "", detail: str = "",
               *, workflow_completed: bool = False):
        if state not in {"COMPLETED", "FAILED", "CANCELLED"}:
            raise ValueError("Invalid terminal progress state.")
        workflow_completed = workflow_completed or state == "COMPLETED"
        if workflow_completed and (state == "CANCELLED" or len(self.done) != len(self.stages)):
            raise ValueError("All stages must finish before workflow completion.")
        self.terminal = True
        self._emit(operation, state, 100.0 if workflow_completed else self.last_percentage,
                   error=error, detail=detail, workflow_completed=workflow_completed)

    def _emit(self, operation, state, percentage, error="", detail="", module_id="", workflow_completed=False):
        stage_status = tuple({"id": sid, "label": label,
                              "state": "completed" if sid in self.done else
                              "active" if sid == self.current else "pending"}
                             for sid, label, _ in self.stages)
        self.callback(ProgressEvent(self.current, operation, state, self.completed,
                                    self.total, percentage, monotonic() - self.started,
                                    module_id=module_id, error=error, detail=detail,
                                    stages=stage_status, workflow_completed=workflow_completed))

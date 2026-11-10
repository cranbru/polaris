import pytest

from core.progress import ProgressTracker, CancellationToken, AcquisitionCancelled, processing_context, observe_operation


def test_weighted_work_and_success_guard():
    events = []
    tracker = ProgressTracker([("collect", "Collect", 80), ("report", "Report", 20)], events.append)
    tracker.update("collect", "Copy", 2, 4)
    assert events[-1].percentage == 40
    with pytest.raises(ValueError):
        tracker.finish("COMPLETED", "Too early")
    tracker.finish_stage("collect", "Collected")
    assert events[-1].percentage == 80  # No double counting a finished stage.
    assert events[-1].completed == events[-1].total == 4
    tracker.update("report", "Render", 1, 2)
    assert events[-1].percentage == 90
    tracker.finish_stage("report", "Saved")
    assert events[-1].percentage < 100
    tracker.finish("COMPLETED", "Done")
    assert events[-1].percentage == 100
    assert all(s["state"] == "completed" for s in events[-1].stages)


@pytest.mark.parametrize("terminal", ["FAILED", "CANCELLED"])
def test_unknown_work_and_interruption_never_reach_100(terminal):
    events = []
    tracker = ProgressTracker([("collect", "Collect", 1)], events.append)
    tracker.update("collect", "Enumerating")
    assert events[-1].state == "INDETERMINATE"
    assert events[-1].percentage is None
    tracker.update("collect", "Acquiring", 1, 3)
    tracker.finish(terminal, "Stopped", error="diagnostic")
    assert events[-1].state == terminal
    assert events[-1].percentage < 100
    tracker.update("collect", "Late notification", 3, 3)
    assert events[-1].state == terminal


def test_cancellation_context_does_not_leak_to_other_runs():
    token = CancellationToken()
    operations = []
    with processing_context(token, lambda name, detail: operations.append(name)):
        observe_operation("Copying")
        token.cancel()
        with pytest.raises(AcquisitionCancelled):
            observe_operation("Must not execute")
    observe_operation("Outside the cancelled run")
    assert operations == ["Copying"]


def test_finished_workflow_with_gaps_reaches_100_without_losing_diagnostics():
    events = []
    tracker = ProgressTracker([("collect", "Collect", 80), ("report", "Report", 20)], events.append)
    tracker.finish_stage("collect", "Collectors processed")
    with pytest.raises(ValueError):
        tracker.finish("FAILED", "Too early", workflow_completed=True)
    tracker.finish_stage("report", "Reports saved")
    assert events[-1].percentage < 100
    tracker.finish("FAILED", "Finished with collection gaps", detail="One collector was partial", workflow_completed=True)
    assert events[-1].percentage == 100
    assert events[-1].state == "FAILED"
    assert events[-1].workflow_completed
    assert events[-1].detail == "One collector was partial"

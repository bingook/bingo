from pathlib import Path

from bingo.core.v7 import MissionEvent, MissionPhase, MissionScope, MissionStateMachine
from bingo.core.v7.report_service import ReportService


def _reporting_mission():
    mission = MissionStateMachine(MissionScope("https://example.test", "report"))
    mission.apply(MissionEvent.START)
    mission.apply(MissionEvent.REPORT_REQUESTED)
    assert mission.phase is MissionPhase.REPORT
    return mission


def test_report_service_completes_only_after_artifacts_exist(tmp_path: Path):
    mission = _reporting_mission()

    def writer():
        markdown = tmp_path / "report.md"
        html = tmp_path / "report.html"
        markdown.write_text("report")
        html.write_text("<p>report</p>")
        return markdown, html

    result = ReportService(mission, writer).generate()

    assert result.completed is True
    assert mission.phase is MissionPhase.DONE
    assert any("report_emitted" in item for item in mission.history)


def test_report_service_keeps_report_phase_when_artifact_missing(tmp_path: Path):
    mission = _reporting_mission()
    missing = tmp_path / "missing.html"

    result = ReportService(mission, lambda: (missing,)).generate()

    assert result.completed is False
    assert mission.phase is MissionPhase.REPORT
    assert "incomplete" in result.error
    assert not any("report_emitted" in item for item in mission.history)


def test_report_service_keeps_report_phase_on_writer_error():
    mission = _reporting_mission()

    def writer():
        raise OSError("disk full")

    result = ReportService(mission, writer).generate()

    assert result.completed is False
    assert result.error == "disk full"
    assert mission.phase is MissionPhase.REPORT

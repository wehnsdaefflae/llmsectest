"""Data models for the llmsectest reporting layer."""

from dataclasses import dataclass, field


@dataclass
class TestResult:
    """Represents a pytest test result."""

    __test__ = False  # not a pytest test class despite the "Test" prefix

    nodeid: str
    location: tuple[str, int, str]  # (file, line, test_name)
    outcome: str  # passed/failed/skipped/error
    longrepr: str | None = None
    duration: float = 0.0
    markers: list[str] = field(default_factory=list)
    properties: dict = field(default_factory=dict)

    @property
    def file_path(self) -> str:
        """Get relative file path."""
        return self.location[0]

    @property
    def line_number(self) -> int:
        """Get test line number."""
        return self.location[1]

    @property
    def test_name(self) -> str:
        """Get test function name."""
        return self.location[2]

    @property
    def docstring(self) -> str | None:
        """Get test docstring from properties."""
        return self.properties.get("docstring")

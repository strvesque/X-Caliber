"""Content panel widget for module outputs."""

from textual.widgets import RichLog


class ContentPanel(RichLog):
    """RichLog panel for displaying module output."""

    def add_output(self, text: str) -> None:
        """Append output text to the panel."""
        _ = self.write(text)

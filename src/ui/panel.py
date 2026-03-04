"""Content panel widget for module outputs and plugin forms."""
from __future__ import annotations

from dataclasses import dataclass
from typing import cast
from collections.abc import Iterable

from rich.console import Group
from rich.pretty import Pretty as RichPretty
from rich.syntax import Syntax
from textual.app import ComposeResult
from typing import override
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, Input, Pretty, Static

from src.core.plugin import BasePlugin


@dataclass(frozen=True)
class FieldSpec:
    name: str
    label: str
    placeholder: str
    default: str
    required: bool = True


class StatusUpdate(Message):
    """Emit status updates for the app status bar."""

    text: str
    level: str

    def __init__(self, text: str, level: str = "info") -> None:
        super().__init__()
        self.text = text
        self.level = level


class ContentPanel(Vertical):
    """Panel that renders plugin forms and formatted results."""

    FIELD_SPECS: dict[str, tuple[FieldSpec, ...]] = {
        "Encoder/Decoder": (
            FieldSpec("data", "Data", "Text to encode/decode", ""),
            FieldSpec("format", "Format", "base64 | hex | url | rot13", "base64"),
            FieldSpec("mode", "Mode", "encode | decode", "encode"),
        ),
        "Hash Identifier & Cracker": (
            FieldSpec("hash", "Hash", "Hash string", ""),
            FieldSpec("mode", "Mode", "identify | crack", "identify"),
            FieldSpec(
                "wordlist",
                "Wordlist",
                "Path to wordlist (optional)",
                "/usr/share/wordlists/rockyou.txt",
                required=False,
            ),
        ),
        "Reverse Shell Generator": (
            FieldSpec("shell_type", "Shell Type", "bash | python | perl | nc", "bash"),
            FieldSpec("lhost", "LHOST", "Your IP address", ""),
            FieldSpec("lport", "LPORT", "Listener port", "4444"),
        ),
        "Port Scanner": (
            FieldSpec("target", "Target", "IP or hostname", ""),
            FieldSpec("ports", "Ports", "22,80,443 or 1-1000", "22,80,443,8080", required=False),
            FieldSpec("scan_type", "Scan Type", "syn | tcp | udp", "syn", required=False),
        ),
        "Subdomain Enumerator": (
            FieldSpec("domain", "Domain", "example.com", ""),
            FieldSpec("engines", "Engines", "google,bing (optional)", "", required=False),
        ),
    }

    def __init__(self) -> None:
        super().__init__()
        self._plugin_cls: type[BasePlugin] | None = None
        self._plugin: BasePlugin | None = None
        self._inputs: dict[str, Input] = {}
        self._last_output: object | None = None
        self._title: Static = Static("Select a plugin from the sidebar", id="panel-title")
        self._description: Static = Static("", id="panel-description")
        self._form_title: Static = Static("Parameters", classes="section-title")
        self._form_fields: Vertical = Vertical(id="form-fields")
        self._run_button: Button = Button("Run Plugin", id="run-plugin", variant="primary")
        self._results_title: Static = Static("Results", classes="section-title")
        self._results_widget: Pretty = Pretty("", id="results")

    @override
    def compose(self) -> ComposeResult:
        yield self._title
        yield self._description
        yield self._form_title
        yield self._form_fields
        with Horizontal(id="form-actions"):
            yield self._run_button
        yield self._results_title
        yield self._results_widget

    def add_output(self, text: str) -> None:
        """Append output text to the panel output area."""
        self._last_output = text
        self._results_widget.update(text)

    def set_plugin(self, plugin_cls: type[BasePlugin]) -> None:
        self._plugin_cls = plugin_cls
        self._plugin = plugin_cls()
        self._plugin.init({})
        self._title.update(plugin_cls.name)
        self._description.update(plugin_cls.description)
        self._build_form(plugin_cls.name)
        self._emit_status(f"Selected {plugin_cls.name}")

    def _build_form(self, plugin_name: str) -> None:
        for child in list(self._form_fields.children):
            _ = child.remove()
        self._inputs = {}

        specs: Iterable[FieldSpec] = self.FIELD_SPECS.get(plugin_name, ())
        if not specs:
            _ = self._form_fields.mount(Static("No parameters required.", classes="empty"))
            return

        for spec in specs:
            label_text = f"{spec.label}{' *' if spec.required else ''}"
            label = Static(label_text, classes="field-label")
            input_widget = Input(value=spec.default, placeholder=spec.placeholder)
            _ = input_widget.add_class("field-input")
            self._inputs[spec.name] = input_widget
            row = Horizontal(label, input_widget, classes="field-row")
            _ = self._form_fields.mount(row)

    def _collect_params(self) -> dict[str, str]:
        if self._plugin_cls is None:
            return {}
        specs = self.FIELD_SPECS.get(self._plugin_cls.name, ())
        params: dict[str, str] = {}
        missing: list[str] = []
        for spec in specs:
            input_widget = self._inputs.get(spec.name)
            value = input_widget.value.strip() if input_widget else ""
            if spec.required and not value:
                missing.append(spec.label)
            if value:
                params[spec.name] = value
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")
        return params

    def run_active_plugin(self) -> None:
        if self._plugin is None or self._plugin_cls is None:
            return
        plugin_cls = self._plugin_cls
        self._emit_status(f"Running {plugin_cls.name}...", level="running")
        try:
            params = self._collect_params()
            self._plugin.run(params)
            results = self._plugin.get_results()
            self._render_results(results)
            if "error" in results:
                error_message = cast(str, results.get("error", "Plugin error"))
                self._emit_status(error_message, level="error")
            else:
                self._emit_status(f"Completed {plugin_cls.name}")
        except Exception as exc:  # noqa: BLE001 - surface friendly error
            self._render_results({"error": str(exc)})
            self._emit_status(f"Error: {exc}", level="error")

    def _render_results(self, results: dict[str, object] | str | list[object]) -> None:
        self._last_output = results
        renderable = RichPretty(results)
        if isinstance(results, dict):
            if "payload" in results and isinstance(results["payload"], str):
                renderable = Group(
                    RichPretty(results),
                    Syntax(results["payload"], "bash", theme="monokai", word_wrap=True),
                )
            elif "output" in results and isinstance(results["output"], str):
                renderable = Group(
                    RichPretty(results),
                    Syntax(results["output"], "text", theme="monokai", word_wrap=True),
                )
        self._results_widget.update(renderable)

    def _emit_status(self, text: str, level: str = "info") -> None:
        _ = self.post_message(StatusUpdate(text, level=level))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-plugin":
            self.run_active_plugin()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        _ = event
        self.run_active_plugin()

"""
Command-line entrypoint for the Red Team Pivot Copilot.

This tool NEVER executes exploits or connects to any network/host. It only
reasons over a provided engagement JSON file (hosts/services/credentials
already discovered by the human operator through their own authorized
tooling) and proposes advisory next steps. Every suggestion requires
explicit human approval before being logged as "approved" — approval does
not trigger any automated action.

Usage:
    pivot-copilot suggest --input sample_data/engagement.json
    pivot-copilot suggest --input sample_data/engagement.json --interactive
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from pivot_copilot.engagement_log import EngagementLog
from pivot_copilot.graph import load_network_graph
from pivot_copilot.suggestions import Suggestion, generate_suggestions

_DISCLAIMER = (
    "This tool is for use ONLY in authorized lab/engagement environments where you have\n"
    "explicit written permission to test. It does not execute exploits or connect to any\n"
    "host — it only suggests advisory next steps for a human operator to review."
)


def _print_suggestion(s: Suggestion, index: int) -> None:
    cred_flag = " (requires credential)" if s.requires_credential else ""
    click.echo(f"[{index}] {s.technique_id} — {s.technique_name}{cred_flag}")
    click.echo(f"    Target: {s.target_host}")
    click.echo(f"    Risk:   {s.risk.upper()}")
    click.echo(f"    Why:    {s.rationale}")
    click.echo("")


@click.group()
def cli() -> None:
    """Lab-only, human-in-the-loop red team pivot reasoning copilot."""


@cli.command()
@click.option(
    "--input", "input_path", required=True, type=click.Path(exists=True),
    help="Path to a JSON file describing the current engagement state (hosts/services/credentials).",
)
@click.option(
    "--interactive", is_flag=True, default=False,
    help="Prompt for approve/reject on each suggestion (human-in-the-loop gate). "
         "Without this flag, suggestions are only listed, not decided.",
)
@click.option(
    "--log-output", "log_output_path", default=None, type=click.Path(),
    help="Path to save the engagement decision log (JSON). Only used with --interactive.",
)
@click.option(
    "--json-only", is_flag=True, default=False,
    help="Print only the JSON suggestion list to stdout (implies non-interactive).",
)
def suggest(
    input_path: str,
    interactive: bool,
    log_output_path: str | None,
    json_only: bool,
) -> None:
    """Generate advisory next-step suggestions for the given engagement state."""
    if not json_only:
        click.echo(_DISCLAIMER)
        click.echo("")

    graph = load_network_graph(input_path)
    suggestions = generate_suggestions(graph)

    if not suggestions:
        click.echo("No further suggestions — no uncompromised reachable hosts with actionable findings.")
        return

    if json_only:
        payload = [
            {
                "suggestion_id": s.suggestion_id,
                "technique_id": s.technique_id,
                "technique_name": s.technique_name,
                "target_host": s.target_host,
                "rationale": s.rationale,
                "risk": s.risk,
                "requires_credential": s.requires_credential,
            }
            for s in suggestions
        ]
        click.echo(json.dumps(payload, indent=2))
        return

    click.echo(f"{len(suggestions)} advisory suggestion(s), highest risk first:\n")
    for idx, s in enumerate(suggestions, start=1):
        _print_suggestion(s, idx)

    if not interactive:
        click.echo("Run with --interactive to review and approve/reject each suggestion.")
        return

    log = EngagementLog()
    click.echo("--- Human-in-the-loop review ---")
    click.echo("Nothing will be executed. Your decision is only recorded in the log.\n")

    for idx, s in enumerate(suggestions, start=1):
        _print_suggestion(s, idx)
        decision = click.prompt(
            "Approve this step for manual execution by you? [y/n/skip]",
            type=click.Choice(["y", "n", "skip"], case_sensitive=False),
            default="skip",
        )
        if decision == "skip":
            continue
        note = click.prompt("Optional note", default="", show_default=False)
        log.record(s, approved=(decision == "y"), operator_note=note)

    click.echo(f"\nRecorded {len(log.decisions)} decision(s) "
               f"({len(log.approved_decisions())} approved).")

    if log_output_path:
        Path(log_output_path).write_text(json.dumps(log.to_dict(), indent=2), encoding="utf-8")
        click.echo(f"Decision log saved to {log_output_path}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()

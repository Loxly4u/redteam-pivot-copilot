from click.testing import CliRunner

from pivot_copilot.cli import cli


def test_suggest_command_lists_suggestions():
    runner = CliRunner()
    result = runner.invoke(cli, ["suggest", "--input", "sample_data/engagement.json"])
    assert result.exit_code == 0
    assert "advisory suggestion" in result.output
    assert "authorized lab" in result.output.lower()


def test_suggest_command_json_only():
    runner = CliRunner()
    result = runner.invoke(cli, ["suggest", "--input", "sample_data/engagement.json", "--json-only"])
    assert result.exit_code == 0
    assert result.output.strip().startswith("[")
    assert "technique_id" in result.output


def test_suggest_command_missing_file_errors():
    runner = CliRunner()
    result = runner.invoke(cli, ["suggest", "--input", "does_not_exist.json"])
    assert result.exit_code != 0


def test_suggest_interactive_approve_and_log(tmp_path):
    log_path = tmp_path / "log.json"
    runner = CliRunner()
    # Simulate: approve first suggestion with a note, skip the rest.
    num_suggestions_guess = 10  # upper bound; CliRunner input just runs out gracefully if fewer prompts
    user_input = "y\napproved for lab test\n" + "skip\n" * num_suggestions_guess
    result = runner.invoke(
        cli,
        ["suggest", "--input", "sample_data/engagement.json", "--interactive",
         "--log-output", str(log_path)],
        input=user_input,
    )
    assert result.exit_code == 0
    assert "Recorded" in result.output
    assert log_path.exists()


def test_suggest_never_mentions_execution_of_exploits():
    """Guard against scope creep: output should never claim to execute anything."""
    runner = CliRunner()
    result = runner.invoke(cli, ["suggest", "--input", "sample_data/engagement.json"])
    lowered = result.output.lower()
    assert "exploit executed" not in lowered
    assert "payload sent" not in lowered
    assert "does not execute exploits" in lowered

#!/usr/bin/env python3
"""
KC7 headless command-line interface (#16).

Runs the same generation pipeline as the web "Start" button, but without the Flask
server — for reproducible runs, CI, and scripted scenarios. Three subcommands:

    python kc7_cli.py validate    # validate every scenario config (offline, CI-friendly)
    python kc7_cli.py preview     # dry-run: what the scenario will generate (offline)
    python kc7_cli.py generate    # run a full generation headlessly

`validate` and `preview` are fully offline (no Azure, no network) and exit non-zero on
problems, so they drop straight into CI. `generate` runs the real pipeline; with
`--no-azure` (or any config where ADX_DEBUG_MODE is on) it generates all telemetry
without uploading to Azure — a complete offline dry-run of the generator.

Exit codes: 0 success, 1 validation/preview/generation error, 2 usage error.
"""

import sys

import click


# Importing the app package builds the Flask app + DB (db.create_all + seed) at import
# time. We do it lazily inside commands so `--help` stays fast and never needs the app.
def _load_app():
    from app import app
    return app


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def cli():
    """KC7 scenario generation — headless CLI."""


@cli.command()
def validate():
    """Validate all scenario configs (actors, malware, company). Offline."""
    app = _load_app()
    from app.server.modules.config_validation.config_validator import validate_all_game_configs
    with app.app_context():
        errors = validate_all_game_configs()
    if errors:
        click.secho("Config validation FAILED:", fg="red", bold=True)
        for e in errors:
            click.echo("  - " + e)
        click.secho(f"\n{len(errors)} problem(s) found.", fg="red")
        sys.exit(1)
    click.secho("All scenario configs are valid.", fg="green", bold=True)


@cli.command()
def preview():
    """Dry run: show what the current scenario will generate, without running it. Offline."""
    app = _load_app()
    from app.server.modules.preview.scenario_preview import preview_scenario, format_preview_text
    with app.app_context():
        data = preview_scenario()
    click.echo(format_preview_text(data))


@cli.command()
@click.option("--no-azure", "force_offline", flag_value=True, default=None,
              help="Force ADX_DEBUG_MODE on: generate everything but don't upload to Azure.")
@click.option("--azure", "force_offline", flag_value=False,
              help="Force a real upload to Azure (overrides a dev ADX_DEBUG_MODE).")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirmation prompt.")
def generate(force_offline, yes):
    """Run a full generation headlessly (same pipeline as the web Start button)."""
    app = _load_app()

    # Resolve the effective upload mode before we touch the pipeline.
    if force_offline is True:
        app.config["ADX_DEBUG_MODE"] = True
    elif force_offline is False:
        app.config["ADX_DEBUG_MODE"] = False
    debug = bool(app.config.get("ADX_DEBUG_MODE"))

    mode = "OFFLINE dry-run (no Azure upload)" if debug else "LIVE — uploading to Azure (ADX)"
    click.secho(f"Generation mode: {mode}", fg=("yellow" if debug else "cyan"), bold=True)

    if not yes:
        click.confirm("This resets the ADX tables and regenerates all data. Continue?", abort=True)

    from app.server.game_functions import start_game, GAME_PROGRESS, _uploader_row_counts

    with app.app_context():
        try:
            start_game()
        except Exception as e:
            click.secho(f"\nGeneration failed: {e}", fg="red", bold=True)
            sys.exit(1)

    # Summarize the outcome from the shared progress dict.
    if GAME_PROGRESS.get("cancelled"):
        click.secho("\nGeneration was cancelled.", fg="yellow")
        sys.exit(1)
    click.secho("\nGeneration complete.", fg="green", bold=True)
    window = (GAME_PROGRESS.get("start_date"), GAME_PROGRESS.get("end_date"))
    if all(window):
        click.echo(f"  Scenario window: {window[0]} -> {window[1]}")
    counts = _uploader_row_counts() or {}
    if counts:
        total = sum(counts.values())
        click.echo(f"  Rows generated: {total:,} across {len(counts)} table(s)")
        for table, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            click.echo(f"    {table:<24} {n:>10,}")
    if debug:
        click.secho("  (offline dry-run — nothing was uploaded to Azure)", fg="yellow")


if __name__ == "__main__":
    cli()

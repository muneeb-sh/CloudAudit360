"""CloudAudit360 command line: serve, scan, report (init is optional)."""

from __future__ import annotations

import sys

import click
from botocore.exceptions import BotoCoreError, ClientError

from app.db import SessionLocal, init_db

NO_CREDS_MSG = (
    "No valid AWS credentials found. Set AWS_PROFILE or "
    "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY. See README."
)

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"], "max_content_width": 100}


def _prepare_db():
    """Create tables, load framework data and the default admin; return an open session."""
    from app.seed import ensure_admin, seed_reference

    init_db()
    db = SessionLocal()
    seed_reference(db)
    ensure_admin(db)
    return db


@click.group(
    context_settings=CONTEXT_SETTINGS,
    epilog="Run `python -m app.cli help COMMAND` (or COMMAND --help) for details and examples.",
)
def cli() -> None:
    """CloudAudit360: read-only AWS security and compliance auditing.

    \b
    Quick start:
      1. python -m app.cli serve      start the dashboard at http://127.0.0.1:8000
      2. Sign in as admin / admin     you will be asked to choose a new password
      3. python -m app.cli scan       scan the AWS account behind your credentials
      4. python -m app.cli report     write an HTML audit report for the latest scan

    \b
    No .env file is needed. Optional settings (AWS_PROFILE, AWS_REGIONS, DATABASE_URL,
    ADMIN_USERNAME, ...) can be put in .env; see .env.example.
    """


@cli.command("help")
@click.argument("command", required=False)
@click.pass_context
def help_cmd(ctx: click.Context, command: str | None) -> None:
    """Show help for all commands, or for one COMMAND.

    \b
    Examples:
      python -m app.cli help
      python -m app.cli help scan
    """
    root = ctx.find_root()
    if command is None:
        click.echo(root.get_help())
        return
    cmd = cli.get_command(root, command)
    if cmd is None:
        names = ", ".join(cli.list_commands(root))
        click.echo(f"Unknown command '{command}'. Available commands: {names}", err=True)
        sys.exit(2)
    with click.Context(cmd, info_name=command, parent=root) as sub_ctx:
        click.echo(cmd.get_help(sub_ctx))


@cli.command("init")
def init_cmd() -> None:
    """Set up the database and admin user (optional).

    `serve`, `scan` and `report` already do this on first run. The admin is
    created as admin / admin (or ADMIN_USERNAME / ADMIN_PASSWORD from .env); with the
    default password you must choose a new one at first sign-in.

    \b
    Example:
      python -m app.cli init
    """
    from app.config import DEFAULT_ADMIN_PASSWORD, get_settings
    from app.seed import ensure_admin, seed_reference

    settings = get_settings()
    init_db()
    db = SessionLocal()
    try:
        seed_reference(db)
        created = ensure_admin(db)
    finally:
        db.close()
    name = settings.admin_username
    if not created:
        click.echo(f"Database ready. Admin user '{name}' already exists.")
    elif settings.admin_password == DEFAULT_ADMIN_PASSWORD:
        click.echo(
            f"Database ready. Admin user '{name}' created with password "
            f"'{DEFAULT_ADMIN_PASSWORD}'; you will be asked to change it at first sign-in."
        )
    else:
        click.echo(f"Database ready. Admin user '{name}' created with ADMIN_PASSWORD from .env.")
    click.echo("Next: python -m app.cli serve")


@cli.command("seed", hidden=True)
@click.pass_context
def seed_cmd(ctx: click.Context) -> None:
    """Deprecated alias for `init`."""
    click.echo("Note: `seed` is deprecated; use `python -m app.cli init`.", err=True)
    ctx.invoke(init_cmd)


@cli.command("reset-admin")
@click.option("--yes", "-y", is_flag=True, help="Do not ask for confirmation.")
def reset_admin_cmd(yes: bool) -> None:
    """Reset the admin password to "admin" if you are locked out.

    The admin must choose a new password at the next sign-in.

    \b
    Example:
      python -m app.cli reset-admin
    """
    from app.config import DEFAULT_ADMIN_PASSWORD, get_settings
    from app.seed import reset_admin_password, seed_reference

    name = get_settings().admin_username
    if not yes:
        click.confirm(f"Reset the password of '{name}' to '{DEFAULT_ADMIN_PASSWORD}'?", abort=True)
    init_db()
    db = SessionLocal()
    try:
        seed_reference(db)
        reset_admin_password(db)
    finally:
        db.close()
    click.echo(
        f"Password for '{name}' reset to '{DEFAULT_ADMIN_PASSWORD}'. "
        "You will be asked to change it at the next sign-in."
    )


@cli.command("scan")
@click.option("--profile", default=None, help="AWS CLI profile (default: AWS_PROFILE or default chain).")
@click.option("--region", "regions", multiple=True, help="Region to scan; repeat for several.")
@click.option("--label", default=None, help='Free-form label, e.g. "prod" or "weekly".')
def scan_cmd(profile: str | None, regions: tuple[str, ...], label: str | None) -> None:
    """Scan the AWS account behind your credentials (read-only).

    Credentials come from the standard AWS chain (profile, environment, SSO, role).
    Without --region, scans AWS_REGIONS, else the profile's region, else every enabled region.

    \b
    Examples:
      python -m app.cli scan
      python -m app.cli scan --profile audit --region us-east-1 --region eu-west-1
      python -m app.cli scan --label prod
    """
    from app.collector.aws_collector import resolve_regions
    from app.pipeline import aws_session, caller_identity, run_scan

    try:
        session = aws_session(profile)
        identity = caller_identity(session)
    except (BotoCoreError, ClientError) as exc:
        click.echo(NO_CREDS_MSG, err=True)
        click.echo(f"  ({exc})", err=True)
        sys.exit(1)

    click.echo(f"Account: {identity['Account']}")
    click.echo(f"Identity: {identity['Arn']}")
    try:
        scan_regions = resolve_regions(session, regions)
    except (BotoCoreError, ClientError) as exc:
        click.echo(f"Could not list regions ({exc}). Pass --region or set AWS_REGIONS.", err=True)
        sys.exit(1)

    db = _prepare_db()
    try:
        scan = run_scan(
            db,
            label=label,
            triggered_by="cli",
            session=session,
            regions=scan_regions,
            identity=identity,
            progress=click.echo,
        )
        _print_summary(db, scan.id)
    finally:
        db.close()


def _print_summary(db, scan_id: int) -> None:
    from app.grc.compliance import framework_scores
    from app.models import Finding

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    count = lambda status: sum(1 for f in findings if f.status == status)  # noqa: E731
    fails = [f for f in findings if f.status == "FAIL"]
    click.echo("")
    click.echo(f"Scan {scan_id} complete")
    click.echo(f"  Checks: {len(findings)}  PASS: {count('PASS')}  FAIL: {count('FAIL')}  ERROR: {count('ERROR')}")
    for s in framework_scores(db, scan_id):
        click.echo(f"  {s.framework:<10} {s.score:.0f}% compliant")
    crit = sum(1 for f in fails if f.severity == "critical")
    high = sum(1 for f in fails if f.severity == "high")
    click.echo(f"  Critical findings: {crit}  High findings: {high}")
    click.echo(f"Next: python -m app.cli report --scan {scan_id}")


@cli.command("report")
@click.option("--scan", "scan_id", type=int, default=None, help="Scan id (default: latest completed scan).")
@click.option("--type", "report_type", type=click.Choice(["audit", "technical"]), default="audit",
              show_default=True, help="Audit summary or detailed technical report.")
@click.option("--format", "fmt", type=click.Choice(["html", "pdf"]), default="html",
              show_default=True, help="PDF needs weasyprint; falls back to HTML.")
def report_cmd(scan_id: int | None, report_type: str, fmt: str) -> None:
    """Write an audit or technical report (latest scan by default).

    \b
    Examples:
      python -m app.cli report
      python -m app.cli report --scan 3 --type technical
      python -m app.cli report --format pdf
    """
    from app.models import Scan
    from app.reporting.builder import generate_report

    db = _prepare_db()
    try:
        if scan_id is None:
            latest = db.query(Scan).filter(Scan.status == "completed").order_by(Scan.id.desc()).first()
            if latest is None:
                click.echo("No completed scans yet. Run `python -m app.cli scan` first.", err=True)
                sys.exit(1)
            scan_id = latest.id
        elif not db.get(Scan, scan_id):
            click.echo(f"Scan {scan_id} not found.", err=True)
            sys.exit(1)
        report = generate_report(db, scan_id=scan_id, report_type=report_type, fmt=fmt)
        db.commit()
        if fmt == "pdf" and report.format != "pdf":
            click.echo("PDF output needs weasyprint (`pip install weasyprint`); wrote HTML instead.", err=True)
        click.echo(f"Report for scan {scan_id}: {report.path}")
    finally:
        db.close()


@cli.command("serve")
@click.option("--port", default=8000, show_default=True, type=int, help="Port to listen on.")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Interface to bind; 0.0.0.0 exposes the dashboard to your network.")
def serve_cmd(port: int, host: str) -> None:
    """Start the web dashboard.

    \b
    Examples:
      python -m app.cli serve
      python -m app.cli serve --port 8080
    """
    import uvicorn

    from app.config import DEFAULT_ADMIN_PASSWORD, get_settings
    from app.seed import admin_has_default_password

    db = _prepare_db()
    try:
        first_run = admin_has_default_password(db)
    finally:
        db.close()
    click.echo(f"Dashboard: http://{host}:{port}")
    if first_run:
        click.echo(
            f"Sign in as '{get_settings().admin_username}' with password "
            f"'{DEFAULT_ADMIN_PASSWORD}'; you will be asked to choose a new one."
        )
    uvicorn.run("app.main:app", host=host, port=port)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()

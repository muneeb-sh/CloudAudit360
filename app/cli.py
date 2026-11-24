"""CloudAudit360 command line: init -> scan -> report -> serve."""

from __future__ import annotations

import sys

import click
from botocore.exceptions import BotoCoreError, ClientError

from app.db import SessionLocal, init_db

NO_CREDS_MSG = (
    "No valid AWS credentials found. Set AWS_PROFILE or "
    "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY. See README."
)


@click.group()
def cli() -> None:
    """CloudAudit360: read-only AWS security and compliance auditing."""


@cli.command("init")
def init_cmd() -> None:
    """Create the database, load framework data, and create the admin user."""
    from app.seed import SetupError, create_admin, seed_reference

    init_db()
    db = SessionLocal()
    try:
        seed_reference(db)
        try:
            created = create_admin(db)
        except SetupError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)
        from app.config import get_settings

        name = get_settings().admin_username
        click.echo(f"Database ready. Admin user '{name}' {'created' if created else 'already exists'}.")
    finally:
        db.close()


@cli.command("seed", hidden=True)
@click.pass_context
def seed_cmd(ctx: click.Context) -> None:
    """Deprecated alias for `init`."""
    click.echo("Note: `seed` is deprecated; use `python -m app.cli init`.", err=True)
    ctx.invoke(init_cmd)


@cli.command("scan")
@click.option("--profile", default=None, help="AWS CLI profile (default: AWS_PROFILE or default chain).")
@click.option("--region", "regions", multiple=True, help="Region to scan; repeat for several.")
@click.option("--label", default=None, help='Free-form label, e.g. "prod" or "weekly".')
def scan_cmd(profile: str | None, regions: tuple[str, ...], label: str | None) -> None:
    """Scan the AWS account behind the active credentials (read-only)."""
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

    init_db()
    db = SessionLocal()
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
@click.option("--type", "report_type", type=click.Choice(["audit", "technical"]), default="audit")
@click.option("--format", "fmt", type=click.Choice(["html", "pdf"]), default="html")
def report_cmd(scan_id: int | None, report_type: str, fmt: str) -> None:
    """Generate an audit or technical report (latest scan by default)."""
    from app.models import Scan
    from app.reporting.builder import generate_report

    init_db()
    db = SessionLocal()
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
@click.option("--port", default=8000, show_default=True, type=int)
@click.option("--host", default="127.0.0.1", show_default=True)
def serve_cmd(port: int, host: str) -> None:
    """Start the dashboard."""
    import uvicorn

    uvicorn.run("app.main:app", host=host, port=port)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()

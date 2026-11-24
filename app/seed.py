from __future__ import annotations

from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from app.auth import hash_password
from app.config import DATA_DIR, DEFAULT_ADMIN_PASSWORD, get_settings
from app.models import CheckControlMap, Control, Policy, User


def load_yaml(path: Path) -> dict | list:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def ensure_admin(db: Session) -> bool:
    """Create the dashboard admin if it does not exist yet. Returns True if created.

    Uses ADMIN_USERNAME / ADMIN_PASSWORD (default admin / admin). With the default
    password the account must change it at first sign-in. An existing user is never touched.
    """
    settings = get_settings()
    if db.query(User).filter(User.username == settings.admin_username).first():
        return False
    db.add(
        User(
            username=settings.admin_username,
            password_hash=hash_password(settings.admin_password),
            role="admin",
            must_change_password=settings.admin_password == DEFAULT_ADMIN_PASSWORD,
        )
    )
    db.commit()
    return True


def reset_admin_password(db: Session) -> User:
    """Set the admin back to the default password and force a change at next sign-in."""
    settings = get_settings()
    user = db.query(User).filter(User.username == settings.admin_username).first()
    if user is None:
        ensure_admin(db)
        user = db.query(User).filter(User.username == settings.admin_username).one()
    user.password_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
    user.role = "admin"
    user.must_change_password = True
    db.commit()
    return user


def admin_has_default_password(db: Session) -> bool:
    """True while the configured admin still has to replace the default password."""
    user = db.query(User).filter(User.username == get_settings().admin_username).first()
    return bool(user and user.must_change_password)


def seed_controls(db: Session) -> dict[tuple[str, str], Control]:
    data = load_yaml(DATA_DIR / "frameworks" / "controls.yaml")
    by_key: dict[tuple[str, str], Control] = {}
    for item in data.get("controls", []):
        key = (item["framework"], str(item["control_ref"]))
        existing = (
            db.query(Control)
            .filter(Control.framework == key[0], Control.control_ref == key[1])
            .first()
        )
        if existing:
            existing.title = item["title"]
            existing.description = item["description"]
            by_key[key] = existing
        else:
            ctrl = Control(
                framework=item["framework"],
                control_ref=str(item["control_ref"]),
                title=item["title"],
                description=item["description"],
            )
            db.add(ctrl)
            db.flush()
            by_key[key] = ctrl
    return by_key


def seed_mapping(db: Session, controls: dict[tuple[str, str], Control]) -> None:
    mapping = load_yaml(DATA_DIR / "frameworks" / "mapping.yaml")
    for check_id, refs in mapping.items():
        for ref in refs:
            key = (ref["framework"], str(ref["ref"]))
            ctrl = controls.get(key)
            if not ctrl:
                continue
            exists = (
                db.query(CheckControlMap)
                .filter(
                    CheckControlMap.check_id == check_id,
                    CheckControlMap.control_id == ctrl.id,
                )
                .first()
            )
            if not exists:
                db.add(CheckControlMap(check_id=check_id, control_id=ctrl.id))


def seed_policies(db: Session, controls: dict[tuple[str, str], Control]) -> None:
    data = load_yaml(DATA_DIR / "policies.yaml")
    for item in data.get("policies", []):
        linked_ids: list[int] = []
        for ref in item.get("linked_controls", []):
            ctrl = controls.get((ref["framework"], str(ref["ref"])))
            if ctrl:
                linked_ids.append(ctrl.id)
        existing = db.query(Policy).filter(Policy.name == item["name"]).first()
        if existing:
            existing.statement = item["statement"].strip()
            existing.linked_control_ids = linked_ids
        else:
            db.add(
                Policy(
                    name=item["name"],
                    statement=item["statement"].strip(),
                    linked_control_ids=linked_ids,
                )
            )


def seed_reference(db: Session) -> None:
    """Load framework controls, check mappings and policies (idempotent)."""
    controls = seed_controls(db)
    db.flush()
    # refresh control map with IDs
    controls = {
        (c.framework, c.control_ref): c for c in db.query(Control).all()
    }
    seed_mapping(db, controls)
    seed_policies(db, controls)
    db.commit()

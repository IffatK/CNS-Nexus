"""Role-aware user filters shared by messaging and file-sharing routes."""
from flask import current_app
from sqlalchemy import and_

from models import User


def client_users(query=None):
    """Return a query that excludes both admin roles and configured admin names.

    The username check also protects installations where an admin account was
    created before its role flag was configured correctly.
    """
    query = query if query is not None else User.query
    query = query.filter(client_user_condition())
    return query


def client_user_condition(model=User):
    admin_names = [name.strip().lower() for name in current_app.config.get("ADMIN_USERNAMES", []) if name.strip()]
    condition = model.is_admin.is_(False)
    if admin_names:
        condition = and_(condition, ~model.username.in_(admin_names))
    return condition


def is_admin_identity(user):
    admin_names = {name.strip().lower() for name in current_app.config.get("ADMIN_USERNAMES", []) if name.strip()}
    return bool(user.is_admin or user.username.strip().lower() in admin_names)

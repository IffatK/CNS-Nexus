from extensions import db
from models.base import utcnow


class UserSigningKey(db.Model):
    """Per-user Ed25519 private key wrapped by the application master key."""
    __tablename__ = "user_signing_keys"
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    wrapped_key = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class ApplicationKeyMaterial(db.Model):
    """Application-wide key material encrypted under the master key."""
    __tablename__ = "application_key_material"
    name = db.Column(db.String(64), primary_key=True)
    encrypted_value = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

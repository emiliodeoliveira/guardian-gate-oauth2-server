import time
import hmac
from datetime import datetime, timezone

from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
from flask_login import UserMixin
from werkzeug.security import check_password_hash

from . import db


class User(UserMixin, db.Model):
    id: str
    name: str
    email: str
    password: str
    date_created: datetime

    id = db.Column(db.String(200), primary_key=True)
    name = db.Column(db.String(1000))
    email = db.Column(db.String(200), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    secret_key = db.Column(db.String(200), nullable=True)
    secret_token = db.Column(db.String(200), nullable=True)
    date_created = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return '<User %r>' % self.id

    def check_password(self, password):
        """Check a plaintext password against the stored hash."""
        return check_password_hash(self.password, password)


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = 'oauth2_client'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.String(200), db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    def check_client_secret(self, client_secret):
        """Verify a provided client_secret against the stored (hashed) secret.
        Returns True if secret matches or if the client has no secret and empty string provided.
        """
        stored = getattr(self, 'client_secret', None) or ''
        try:
            return check_password_hash(stored, client_secret)
        except Exception:
            # Fallback to constant time compare if stored is plaintext
            return hmac.compare_digest(stored, client_secret or '')


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = 'oauth2_code'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.String(200), db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = 'oauth2_token'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.String(200), db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    def is_refresh_token_active(self):
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()

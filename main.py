import time
import base64

from authlib.oauth2 import OAuth2Error
from flask import Blueprint, render_template, redirect, request, session, url_for, jsonify
from flask_login import login_required, current_user
from werkzeug.security import gen_salt
from werkzeug.security import generate_password_hash

from . import db
from .models import OAuth2Client, User, OAuth2Token
from .oauth2 import authorization

main = Blueprint('main', __name__)


def get_session_user():
    """Return the logged-in User instance from the session, or None."""
    if 'user_id' not in session:
        return None
    user_id = session.get('user_id')
    return User.query.get(user_id)


def split_function(s):
    return [v for v in s.splitlines() if v]


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/profile')
@login_required
def profile():
    clients = OAuth2Client.query.filter_by(user_id=current_user.id)
    return render_template('profile.html', name=current_user.name, clients=clients)


@main.route('/client/new', methods=['POST'])
def new_client():
    """Create a new OAuth2 client

    ---
    tags:
      - clients
    consumes:
      - application/x-www-form-urlencoded
      - multipart/form-data
    parameters:
      - name: client_name
        in: formData
        required: true
        type: string
      - name: client_uri
        in: formData
        required: false
        type: string
      - name: grant_type
        in: formData
        required: true
        type: string
      - name: redirect_uri
        in: formData
        required: true
        type: string
      - name: response_type
        in: formData
        required: true
        type: string
      - name: scope
        in: formData
        required: false
        type: string
      - name: token_endpoint_auth_method
        in: formData
        required: true
        type: string
    responses:
      302:
        description: Redirect to client profile or client info page
    """
    user = get_session_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        return render_template('new_client.html')

    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id=user.id,
    )

    form = request.form
    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_function(form["grant_type"]),
        "redirect_uris": split_function(form["redirect_uri"]),
        "response_types": split_function(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"]
    }
    client.set_client_metadata(client_metadata)

    if form['token_endpoint_auth_method'] == 'none':
        client.client_secret = ''
    else:
        # Generate a raw secret, store a hashed version in DB and keep the raw secret in session
        raw_secret = gen_salt(48)
        client.client_secret = generate_password_hash(raw_secret, method='pbkdf2:sha256')

    db.session.add(client)
    db.session.commit()
    # Store the raw secret in session for one-time display on client info page
    session['last_client_id'] = client.client_id
    session['last_client_secret'] = raw_secret if 'raw_secret' in locals() else None
    return redirect(f'/client_info?client_id={client.client_id}')


@main.route('/client/info', methods=['GET'])
@login_required
def client_info():
    """Get client information (HTML page)

    ---
    tags:
      - clients
    parameters:
      - name: client_id
        in: query
        required: true
        type: string
    responses:
      200:
        description: Client info page (HTML)
    """
    client_id = request.args.get('client_id')
    client = OAuth2Client.query.filter_by(client_id=client_id).first()
    # Pop any one-time secret for display
    one_time_secret = None
    if session.get('last_client_id') == client_id:
        one_time_secret = session.pop('last_client_secret', None)
        session.pop('last_client_id', None)
    return render_template('client_info.html', client=client, one_time_secret=one_time_secret)


@main.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    """Authorize endpoint (consent)

    This endpoint renders the consent screen on GET and handles the consent response on POST.

    ---
    tags:
      - oauth2
    parameters:
      - name: response_type
        in: query
        required: true
        type: string
      - name: client_id
        in: query
        required: true
        type: string
      - name: redirect_uri
        in: query
        required: false
        type: string
      - name: scope
        in: query
        required: false
        type: string
    responses:
      200:
        description: Consent HTML page
      302:
        description: Redirect to client redirect_uri with code/error
    """
    user = get_session_user()
    if not user:
        return redirect(url_for('auth.login', next=request.url))
    if request.method == 'GET':
        try:
            grant = authorization.get_consent_grant(end_user=user)
        except OAuth2Error as error:
            return error.error
        return render_template('authorize.html', user=user, grant=grant)
    if not user and 'username' in request.form:
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
    if request.form['confirm']:
        grant_user = user
    else:
        grant_user = None
    return authorization.create_authorization_response(grant_user=grant_user)


@main.route('/oauth/token', methods=['POST'])
def issue_token():
    """Token endpoint

    Exchange an authorization grant for an access token.

    ---
    tags:
      - oauth2
    consumes:
      - application/x-www-form-urlencoded
    parameters:
      - name: grant_type
        in: formData
        required: true
        type: string
      - name: code
        in: formData
        required: false
        type: string
      - name: redirect_uri
        in: formData
        required: false
        type: string
      - name: client_id
        in: formData
        required: false
        type: string
      - name: client_secret
        in: formData
        required: false
        type: string
    responses:
      200:
        description: JSON with access_token, token_type, expires_in, refresh_token
    """
    return authorization.create_token_response()


@main.route('/oauth/revoke', methods=['POST'])
def revoke_token():
    """Revocation endpoint

    Revoke an access or refresh token.

    ---
    tags:
      - oauth2
    consumes:
      - application/x-www-form-urlencoded
    parameters:
      - name: token
        in: formData
        required: true
        type: string
      - name: token_type_hint
        in: formData
        required: false
        type: string
    responses:
      200:
        description: Token was revoked (empty body)
    """
    return authorization.create_endpoint_response('revocation')


def _authenticate_client():
    """Authenticate client using HTTP Basic auth or form-encoded client_id/client_secret.
    Returns the OAuth2Client instance or None.
    """
    auth = request.headers.get('Authorization')
    client_id = None
    client_secret = None
    if auth and auth.lower().startswith('basic '):
        try:
            b64 = auth.split(None, 1)[1].strip()
            decoded = base64.b64decode(b64).decode('utf-8')
            client_id, client_secret = decoded.split(':', 1)
        except Exception:
            return None
    else:
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')

    if not client_id:
        return None
    client = OAuth2Client.query.filter_by(client_id=client_id).first()
    if not client:
        return None
    # Use the model helper which supports hashed secrets and constant-time compare
    if client.check_client_secret(client_secret or ''):
        return client
    return None


@main.route('/oauth/introspect', methods=['POST'])
def introspect():
    """Token introspection endpoint (RFC 7662)

    Clients must authenticate and post a `token` form parameter.

    ---
    tags:
      - oauth2
    consumes:
      - application/x-www-form-urlencoded
    parameters:
      - name: token
        in: formData
        required: true
        type: string
    responses:
      200:
        description: JSON indicating token activity and metadata
    """
    client = _authenticate_client()
    if not client:
        # RFC 7009/7662: 401 for invalid client authentication
        return ('Unauthorized', 401)

    token = request.form.get('token')
    if not token:
        return jsonify({'active': False})

    tok = OAuth2Token.query.filter((OAuth2Token.access_token == token) | (OAuth2Token.refresh_token == token)).first()
    if not tok:
        return jsonify({'active': False})

    # Check revoked or expired
    if getattr(tok, 'revoked', False):
        return jsonify({'active': False})

    exp = None
    try:
        exp = tok.issued_at + int(tok.expires_in)
    except Exception:
        exp = None

    active = True
    if exp is not None and exp < time.time():
        active = False

    if not active:
        return jsonify({'active': False})

    resp = {
        'active': True,
        'scope': tok.scope if hasattr(tok, 'scope') else '',
        'client_id': tok.client_id if hasattr(tok, 'client_id') else None,
        'username': tok.user_id if hasattr(tok, 'user_id') else None,
        'token_type': tok.token_type if hasattr(tok, 'token_type') else None,
        'exp': exp,
        'iat': getattr(tok, 'issued_at', None),
        'sub': tok.user_id if hasattr(tok, 'user_id') else None,
    }
    return jsonify(resp)

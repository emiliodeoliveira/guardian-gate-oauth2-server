import importlib.util
import sys
from pathlib import Path
import base64
from datetime import datetime
import time

# load package __init__.py as module
pkg_path = Path(__file__).resolve().parent.parent / '__init__.py'
spec = importlib.util.spec_from_file_location('app_pkg', str(pkg_path))
app_pkg = importlib.util.module_from_spec(spec)
sys.modules['app_pkg'] = app_pkg
spec.loader.exec_module(app_pkg)

app = app_pkg.create_app()

from werkzeug.security import generate_password_hash
import importlib
models_mod = importlib.import_module('app_pkg.models')
User = models_mod.User
OAuth2Client = models_mod.OAuth2Client
OAuth2Token = models_mod.OAuth2Token
db = importlib.import_module('app_pkg').db

with app.app_context():
    # cleanup for test
    db.session.query(OAuth2Token).delete()
    db.session.query(OAuth2Client).delete()
    db.session.query(User).delete()
    db.session.commit()

    # create a user
    u = User(id='test-user', email='test@example.com', name='Test', password=generate_password_hash('pass'))
    db.session.add(u)
    db.session.commit()

    # create a client with hashed secret
    raw_secret = 'rawsecret123'
    client = OAuth2Client(client_id='test-client', client_id_issued_at=int(time.time()), user_id=u.id)
    client.set_client_metadata({
        'client_name': 'test client',
        'grant_types': ['client_credentials'],
        'redirect_uris': [],
        'response_types': [],
        'scope': 'read',
        'token_endpoint_auth_method': 'client_secret_post'
    })
    client.client_secret = generate_password_hash(raw_secret)
    db.session.add(client)
    db.session.commit()

    # create an access token
    tok = OAuth2Token(
        access_token='atoken123',
        refresh_token='rtoken123',
        issued_at=int(time.time()),
        expires_in=3600,
        token_type='bearer',
        scope='read',
        client_id=client.client_id,
        user_id=u.id,
    )
    db.session.add(tok)
    db.session.commit()

    # call introspect with basic auth header
    auth_value = base64.b64encode(f"{client.client_id}:{raw_secret}".encode()).decode()
    client_t = app.test_client()
    resp = client_t.post('/oauth/introspect', data={'token': 'atoken123'}, headers={'Authorization': f'Basic {auth_value}'})
    print('status', resp.status_code)
    print('json', resp.get_json())

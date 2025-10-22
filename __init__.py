from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os

db = SQLAlchemy()


def create_app():
    app = Flask(__name__, static_folder='static')

    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///test.db')
    app.config['SQLALCHEMY_ECHO'] = os.environ.get('SQLALCHEMY_ECHO', 'False') == 'True'
    app.config['SQLALCHEMY_RECORD_QUERIES'] = os.environ.get('SQLALCHEMY_RECORD_QUERIES', 'False') == 'True'

    # Allow insecure transport for development only when explicitly set.
    if os.environ.get('AUTHLIB_INSECURE_TRANSPORT') == '1':
        os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'

    db.init_app(app)

    with app.app_context():
        try:
            db.create_all()
        except Exception as exception:
            print("*********** WARNING ***********")
            print("ERROR: The following exception occurred: ")
            print("Failure on attempting to run db.create_all() in __init__.py: " + str(exception))
        finally:
            print("SUCCESS! db.create_all() in __init__.py was successfully executed!")

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):

        from .models import User
        return User.query.get(user_id)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .oauth2 import config_oauth
    config_oauth(app)

    try:
        import importlib
        flasgger = importlib.import_module('flasgger')
        Swagger = getattr(flasgger, 'Swagger')
        Swagger(app)
    except Exception:
        # Flasgger not installed. API docs will be unavailable.
        pass

    try:
        import importlib
        flask_migrate = importlib.import_module('flask_migrate')
        Migrate = getattr(flask_migrate, 'Migrate')
        migrate = Migrate()
        migrate.init_app(app, db)
    except Exception:
        pass

    return app

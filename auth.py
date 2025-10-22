from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from .models import User
from datetime import datetime
from . import db
import uuid
from sqlalchemy.exc import IntegrityError

auth = Blueprint('auth', __name__)


@auth.route('/login')
def login():
    return render_template('login.html')


@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user_data = User.query.filter_by(email=email).first()

    if not user_data or not check_password_hash(user_data.password, password):
        flash('Error: Please check your login details and try again.')
        return redirect(url_for('auth.login'))

    login_user(user_data, remember=remember)
    session['user_id'] = user_data.id
    return redirect(url_for('main.profile'))


@auth.route('/signup')
def signup():
    return render_template('signup.html')


@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user_data = User.query.filter_by(email=email).first()

    if user_data is not None:
        flash('This email address already exists')
        return redirect(url_for('auth.signup'))

    new_user = User(id=str(uuid.uuid4()),
                    email=email,
                    name=name,
                    password=generate_password_hash(password, method='pbkdf2:sha256'),
                    date_created=datetime.utcnow()
                    )

    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash('This email address already exists')
        return redirect(url_for('auth.signup'))

    return redirect(url_for('auth.login'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

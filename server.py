import flask
from flask import Flask, session, url_for, redirect, request, render_template, abort, flash, Markup
from datetime import datetime
from urllib.request import Request, urlopen, URLError
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import bcrypt
import os
import markdown
import functools
from authlib.client import OAuth2Session
import google.oauth2.credentials
import googleapiclient.discovery

app = Flask(__name__)
chiavi = open("conf.txt", 'r')
dati = chiavi.readline()
gcid, gcsk = dati.split("|", 1)
app.secret_key = "debug-attivo"
UPLOAD_FOLDER = './static/upload-area'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif', 'svg', 'mp4', 'avi'])
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)

# Oauth configuration

ACCESS_TOKEN_URI = 'https://www.googleapis.com/oauth2/v4/token'
AUTHORIZATION_URL = 'https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&prompt=consent'
AUTHORIZATION_SCOPE = 'openid email profile'
AUTH_REDIRECT_URI = "http://127.0.0.1:5000/google/auth"
BASE_URI = "http://127.0.0.1:5000"
CLIENT_ID = gcid
CLIENT_SECRET = gcsk
AUTH_TOKEN_KEY = 'auth_token'
AUTH_STATE_KEY = 'auth_state'
USER_INFO_KEY = 'user_info'

app.config.from_object(__name__)


# Database classes go beyond this line


class Qr(db.Model):
    qid = db.Column(db.Integer, primary_key=True)
    free = db.Column(db.Boolean, nullable=False)
    content_type = db.Column(db.Integer, nullable=False)
    content_link = db.Column(db.String, nullable=False)

    # TODO: Add relationship between user and qr to establish ownership

    def __init__(self):
        self.free = True

    def __repr__(self):
        return "{}-{}-{}".format(self.qid, self.free, self.content_type)

    def allocate(self, content_type, content_link):
        self.content_type = content_type
        self.content_link = content_link
        self.free = False

    def deallocate(self):
        self.free = True


class User(db.Model):
    uid = db.Column(db.Integer, primary_key=True)
    social_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String, nullable=False)
    surname = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)

    def __init__(self, sid, name, surname, email):
        self.social_id = sid
        self.name = name
        self.surname = surname
        self.email = email

    def __repr__(self):
        return "{}, {}, {}".format(self.uid, self.social_id, self.email)


# Functions go beyond this line

def locate_qr(id):
    return Qr.query.get_or_404(id)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_markdown(raw):
    return Markup(markdown.markdown(raw))


def no_cache(view):  # No_cache function. Deletes the cache during the login phase
    @functools.wraps(view)
    def no_cache_impl(*args, **kwargs):
        response = flask.make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response

    return functools.update_wrapper(no_cache_impl, view)


def is_logged_in():
    return True if AUTH_TOKEN_KEY in flask.session else False


def build_credentials():
    if not is_logged_in():
        raise Exception('L\'utente DEVE essere loggato.')

    oauth2_tokens = flask.session[AUTH_TOKEN_KEY]
    return google.oauth2.credentials.Credentials(
        oauth2_tokens['access_token'],
        refresh_token=oauth2_tokens['refresh_token'],
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        token_uri=ACCESS_TOKEN_URI)


def get_user_info():
    credentials = build_credentials()
    oauth2_client = googleapiclient.discovery.build('oauth2', 'v2', credentials=credentials)
    return oauth2_client.userinfo().get().execute()


def find_user(email):
    return User.query.filter_by(email=email).first()


# Webpages go beyond this line

@app.route('/')
def page_root():
    return redirect(url_for('google_login'))


@app.route('/pre-login/<int:id>')
def page_prelogin(id):
    session[str(request.remote_addr)] = id
    print(session[str(request.remote_addr)])
    return redirect(url_for('google_login'))


@app.route('/login')
def page_login():
    if is_logged_in():
        user_info = get_user_info()
        user = User.query.filter_by(social_id=user_info['id']).first()
        if user:
            session['email'] = user.email
        else:
            nuser = User(user_info['id'], user_info['given_name'], user_info['family_name'], user_info['email'])
            db.session.add(nuser)
            db.session.commit()
            session['email'] = nuser.email
        return redirect(url_for('page_qr', id=0))
    else:
        return abort(403)


@app.route('/dashboard')  # Testing purposes
def page_dashboard():
    if 'email' not in session:
        return abort(403)
    user = find_user(session['email'])
    return "Benvenuto, {} {}!".format(user.name, user.surname)


@app.route('/qr/<int:id>')
def page_qr(id):
    qr = Qr.query.filter_by(qid=id).first()
    try:
        user = find_user(session['email'])
        if user and not qr:
            print(session[str(request.remote_addr)])
            id = session[str(request.remote_addr)]
    except KeyError:
        user = None
    return render_template("qr/show.htm", qr=qr, user=user, id=id)


@app.route('/google/login')
@no_cache
def google_login():
    session = OAuth2Session(CLIENT_ID, CLIENT_SECRET, scope=AUTHORIZATION_SCOPE, redirect_uri=AUTH_REDIRECT_URI)
    uri, state = session.authorization_url(AUTHORIZATION_URL)
    flask.session[AUTH_STATE_KEY] = state
    flask.session.permanent = True
    return flask.redirect(uri, code=302)


@app.route('/google/auth')
@no_cache
def google_auth_redirect():
    state = flask.request.args.get('state', default=None, type=None)
    session = OAuth2Session(CLIENT_ID, CLIENT_SECRET, scope=AUTHORIZATION_SCOPE, state=state,
                            redirect_uri=AUTH_REDIRECT_URI)
    oauth2_tokens = session.fetch_access_token(ACCESS_TOKEN_URI, authorization_response=flask.request.url)
    flask.session[AUTH_TOKEN_KEY] = oauth2_tokens

    return flask.redirect(url_for('page_login'), code=302)


@app.route('/logout')
@no_cache
def logout():
    flask.session.pop(AUTH_TOKEN_KEY, None)
    flask.session.pop(AUTH_STATE_KEY, None)
    flask.session.pop(USER_INFO_KEY, None)
    session.pop('email')
    return flask.redirect(url_for('page_root'))


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)

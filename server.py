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
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif', 'svg', 'mp4', 'avi', 'mp3'])
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
    __tablename__ = "qr"
    qid = db.Column(db.Integer, primary_key=True, autoincrement=False)
    content_type = db.Column(db.Integer, nullable=False)
    content_link = db.Column(db.String, nullable=False)
    title = db.Column(db.String, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.uid'))
    owner = db.relationship("User", back_populates="qrs")

    def __init__(self, content_type, content_link, owner_id, title, qid):
        self.content_type = content_type
        self.content_link = content_link
        self.owner_id = owner_id
        self.title = title
        self.qid = qid

    def __repr__(self):
        return "{}-{}-{}".format(self.qid, self.content_type)


class User(db.Model):
    __tablename__ = "user"
    uid = db.Column(db.Integer, primary_key=True)
    social_id = db.Column(db.BigInteger, nullable=False)
    name = db.Column(db.String, nullable=False)
    surname = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False)
    qrs = db.relationship("Qr", back_populates="owner")
    orders = db.relationship("Order", back_populates="user")

    def __init__(self, sid, name, surname, email):
        self.social_id = sid
        self.name = name
        self.surname = surname
        self.email = email
        self.is_admin = False

    def __repr__(self):
        return "{}, {}, {}".format(self.uid, self.social_id, self.email)


class Order(db.Model):
    __tablename__ = "order"
    oid = db.Column(db.Integer, primary_key=True)
    user = db.relationship("User", back_populates="orders")
    user_id = db.Column(db.Integer, db.ForeignKey('user.uid'))
    qr_id = db.Column(db.Integer, nullable=False)
    order_size = db.Column(db.Integer, nullable=False)

    def __init__(self, user_id, qr_id, order_size):
        self.user_id = user_id
        self.qr_id = qr_id
        self.order_size = order_size

    def __repr__(self):
        return "{}-{}->{}".format(self.oid, self.user_id, self.qr_id)


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


# Login-specific webpages go beyond this line

@app.route('/')
def page_root():
    if 'email' not in session:
        user = None
    else:
        user = find_user(session['email'])
    return render_template("main.htm", user=user)


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
            if len(User.query.all()) == 0:
                nuser.is_admin = True
            db.session.add(nuser)
            db.session.commit()
            session['email'] = nuser.email
        try:
            id = session[str(request.remote_addr)]
        except:
            return redirect(url_for('page_root'))
        return redirect(url_for('page_qr', id=0))
    else:
        return abort(403)


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


# Webpages go beyond this line


@app.route('/qr/<int:id>')
def page_qr(id):
    qr = Qr.query.filter_by(qid=id).first()
    try:
        user = find_user(session['email'])
        if user and not qr:
            if id == 0:
                id = session[str(request.remote_addr)]
                session.pop(str(request.remote_addr))
    except KeyError:
        user = None
    if qr and qr.content_type == 1:
        type = qr.content_link.rsplit('.', 1)[1].lower()
        print(type)
    else:
        type = None
    return render_template("qr/show.htm", qr=qr, user=user, id=id, type=type)


@app.route('/qr_allocate/<int:mode>/<int:id>', methods=["POST", "GET"])
def page_qr_allocate(mode, id):
    if 'email' not in session:
        return abort(403)
    qr = Qr.query.filter_by(qid=id).first()
    user = find_user(session['email'])
    if qr and qr.owner_id != user.uid:
        return abort(403)
    if request.method == "GET":
        return render_template("qr/allocate.htm", mode=mode, id=id, user=user)
    if mode == 4:
        nqr = Qr(mode, request.form['url'], user.uid, request.form['title'], id)
    else:
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = str(id) + '.' + str(file.filename.rsplit('.', 1)[1].lower())
            flash(
                "Caricamento file in corso. A seconda delle dimensioni del file, potrebbe essere necessario attendere parecchio. Non chiudere questa pagina.")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            fullpath = app.config['UPLOAD_FOLDER'] + "/" + filename
            nqr = Qr(mode, fullpath, user.uid, request.form['title'], id)
    db.session.add(nqr)
    db.session.commit()
    return redirect(url_for('page_profile_quickits'))


@app.route("/qr_remove/<int:id>", methods=["POST", "GET"])
def page_qr_remove(id):
    if 'email' not in session:
        return abort(403)
    qr = Qr.query.filter_by(qid=id).first()
    user = find_user(session['email'])
    if qr and qr.owner_id != user.uid and not user.is_admin:
        return abort(403)
    qr = Qr.query.get_or_404(id)
    ordini = Order.query.filter_by(qr_id=id).all()
    for ordine in ordini:
        db.session.delete(ordine)
    if qr.content_type == 4:
        pass
    else:
        os.remove(qr.content_link)
    db.session.delete(qr)
    db.session.commit()
    if user.is_admin:
        return redirect(url_for("page_administration_qr_list"))
    return redirect(url_for("page_profile_quickits"))


@app.route("/qr_edit/<int:id>/<int:mode>", methods=["POST", "GET"])
def page_qr_edit(id, mode):
    if 'email' not in session:
        return abort(403)
    qr = Qr.query.filter_by(qid=id).first()
    user = find_user(session['email'])
    if qr and qr.owner_id != user.uid and not user.is_admin:
        return abort(403)
    if request.method == "GET":
        return render_template("qr/edit.htm", qr=qr, mode=mode, user=user)
    if mode == 1:
        qr.title = request.form['title']
        db.session.commit()
        return redirect(url_for("page_qr", id=id))
    else:
        tipo = request.form['select']
        return redirect(url_for("page_qr_reallocate", id=id, mode=tipo))


@app.route("/qr_reallocate/<int:id>/<int:mode>", methods=["POST", "GET"])
def page_qr_reallocate(id, mode):
    if 'email' not in session:
        return abort(403)
    qr = Qr.query.filter_by(qid=id).first()
    user = find_user(session['email'])
    if qr and qr.owner_id != user.uid and not user.is_admin:
        return abort(403)
    if request.method == "GET":
        return render_template("qr/reallocate.htm", qr=qr, mode=mode, user=user)
    else:
        if qr.content_type == 4:
            pass
        else:
            os.remove(qr.content_link)
        qr.content_type = mode
        if mode == 4:
            qr.content_link = request.form['url']
        else:
            if 'file' not in request.files:
                return redirect(request.url)
            file = request.files['file']
            if file.filename == '':
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = str(id) + '.' + str(file.filename.rsplit('.', 1)[1].lower())
                flash(
                    "Caricamento file in corso. A seconda delle dimensioni del file, potrebbe essere necessario attendere parecchio. Non chiudere questa pagina.")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                fullpath = app.config['UPLOAD_FOLDER'] + "/" + filename
                qr.content_link = fullpath
        db.session.commit()
        return redirect(url_for("page_qr", id=id))




@app.route("/profile/quickits")
def page_profile_quickits():
    if 'email' not in session:
        return abort(403)
    user = find_user(session['email'])
    if not user:
        return abort(403)
    quickits = Qr.query.filter_by(owner_id=user.uid).all()
    return render_template("/profile/quickits.htm", user=user, quickits=quickits)


@app.route("/administration/dash")
def page_administration_dash():
    if 'email' not in session:
        return abort(403)
    user = find_user(session['email'])
    if not user or not user.is_admin:
        return abort(403)
    ordini = Order.query.all()
    numero = 0
    for ordine in ordini:
        numero += ordine.order_size
    return render_template("/administration/dashboard.htm", user=user, numero=numero)


@app.route("/administration/userlist")
def page_administration_users_list():
    if 'email' not in session:
        return abort(403)
    user = find_user(session['email'])
    if not user or not user.is_admin:
        return abort(403)
    users = User.query.all()
    return render_template("/administration/userlist.htm", users=users, user=user)


@app.route("/administration/qrlist")
def page_administration_qr_list():
    if 'email' not in session:
        return abort(403)
    user = find_user(session['email'])
    if not user or not user.is_admin:
        return abort(403)
    qr = Qr.query.all()
    return render_template("/administration/qrlist.htm", qr=qr, user=user)


@app.route("/administration/qr_user/<int:uid>")
def page_administration_qr_user(uid):
    if 'email' not in session:
        return abort(403)
    user = find_user(session['email'])
    if not user or not user.is_admin:
        return abort(403)
    qr = Qr.query.filter_by(owner_id=uid)
    return render_template("/administration/qrlist.htm", qr=qr, user=user)


@app.route("/administration/user/<int:id>/<int:mode>")
def page_administration_user(id, mode):
    if 'email' not in session:
        return abort(403)
    user = find_user(session['email'])
    if not user or not user.is_admin:
        return abort(403)
    utente = User.query.get_or_404(id)
    if mode == 1:
        return render_template("/administration/user_details.htm", utente=utente, user=user)
    if mode == 2:
        return render_template("/administration/promote.htm", utente=utente, user=user)
    if id != utente.uid:
        utente.is_admin = not utente.is_admin
    return redirect(url_for("page_administration_users_list"))


@app.route("/orders/add/<int:qid>", methods=["GET", "POST"])
def page_orders_add(qid):
    if 'email' not in session:
        return abort(403)
    user = find_user(session['email'])
    qr = Qr.query.filter_by(qid=qid, owner_id=user.uid).first()
    if not qr:
        return abort(403)
    if request.method == "GET":
        return render_template("/orders/neworder.htm", user=user, qr=qr)
    neworder = Order(user.uid, qr.qid, request.form["numero"])
    db.session.add(neworder)
    db.session.commit()
    return redirect(url_for("page_orders_inspect"))


@app.route("/orders/inspect")
def page_orders_inspect():
    if 'email' not in session:
        return abort(403)
    user = find_user(session['email'])
    if user.is_admin:
        orders = Order.query.join(User).all()
    else:
        orders = Order.query.filter_by(user_id=user.uid).all()
    return render_template("/orders/list.htm", user=user, orders=orders)


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True, host="0.0.0.0")

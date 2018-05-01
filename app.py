#!/usr/bin/python 

from flask import Flask, render_template, request, redirect, session, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from os import urandom
from ldap3 import Server, Connection, ALL
from configparser import ConfigParser
from scraper import *
from lib import *
from html import escape
from time import strftime,time
from datetime import datetime,timedelta
from hashlib import sha256

app = Flask(__name__)
app.secret_key = urandom(12)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

cfg = ConfigParser()
cfg.read('settings.cfg')
identikey_ldap = cfg['identikey_ldap']['identikey_ldap']
identikey_ldap_dc = cfg['identikey_ldap']['identikey_ldap_dc']
app.config['SQLALCHEMY_DATABASE_URI'] = cfg['database']['database']


admins = ["cala9649"]


class User(db.Model):
    __tablename__ = 'users'

    userID = db.Column(db.String(10), primary_key=True, nullable=False)
    displayName = db.Column(db.String(40), nullable=False)
    ip_agent = db.Column(db.String(100))
    authenticated = False

    def __init__(self, userID):
        self.userID = escape(userID)
        self.displayName = escape(userID)

    def is_active(self):
        return True
    
    def is_authenticated(self):
        return self.authenticated
    
    def get_id(self):
        return self.userID

    def __repr__(self):
        return "User <userID={}, displayName={}, ip_agent={}>".format(self.userID, self.displayName, self.ip_agent)

class Base(db.Model):
    __tablename__ = 'bases'

    baseID = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    branch = db.Column(db.String(50), nullable=False)
    majcom = db.Column(db.String(50), nullable=False)
    geo = db.Column(db.String(10), nullable=False)
    lat = db.Column(db.Float, nullable=False)
    lon = db.Column(db.Float, nullable=False)
    descr = db.Column(db.String(500), nullable=False)

    def __init__(self, name, lat, lon):
        self.name = escape(name)
        self.lat = float(lat)
        self.lon = float(lon)
        self.geo = "CONUS"
        self.descr = ""
        self.branch = ""
        self.majcom = ""
        self.city = ""

class Friend(db.Model):
    __tablename__ = 'friends'

    friendID = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    fname = db.Column(db.String(25), nullable=False)
    lname = db.Column(db.String(25), nullable=False)

    def __init__(self, fname, lname):
        self.fname = escape(fname)
        self.lname = escape(lname)

class Job(db.Model):
    __tablename__ = 'jobs'

    jobID = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    friendID = db.Column(db.Integer, db.ForeignKey('friends.friendID'), nullable=False)
    baseID = db.Column(db.Integer, db.ForeignKey('bases.baseID'), nullable=False)
    title = db.Column(db.String(50), nullable=False)
    start = db.Column(db.Date, nullable=False)
    end = db.Column(db.Date, nullable=False)
    current = db.Column(db.Boolean, nullable=False)
    tdy = db.Column(db.Boolean, nullable=False)

    def __init__(self, title, friendID, baseID, start, end, current, tdy):
        self.title = escape(title)
        self.friendID = int(friendID)
        self.baseID = int(baseID)
        self.start = verify_date(start)
        self.end = verify_date(end)
        self.current = bool(current)
        self.tdy = bool(tdy)

class Login(db.Model):
    __tablename__ = 'logins'

    userID = db.Column(db.String(10), primary_key=True, nullable=False)
    time = db.Column(db.DateTime, default=datetime.now, primary_key=True, nullable=False)
    ip = db.Column(db.String(20), nullable=False)
    success = db.Column(db.Boolean, nullable=False)

    def __init__(self, userID, ip, success):
        self.userID = userID
        self.ip = ip
        self.success = success

def get_bases():
    bases = Base.query.order_by(Base.name)
    base_arr = []
    for base in bases:
        base_arr.append({'name': escape(base.name),
                         'baseID': escape(str(base.baseID)),
                         'varname': escape(generate_varname(base.name)),
                         'lat': escape(str(base.lat)),
                         'lon': escape(str(base.lon))})
    return base_arr

    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def index():
    return redirect("/map")

@app.route('/map')
def map():
    base_arr = get_bases()
    return render_template("map.html", base_arr=base_arr)

@app.route('/login', methods=["GET", "POST"])
def login():
    session.pop('_flashes', None)
    if request.method == "POST":
        ip = request.remote_addr
        past_24 = datetime.today() - timedelta(days=1)
        failed_logins = Login.query.filter_by(ip=ip).filter(Login.success == 0).filter(Login.time >= past_24).all()
        if len(failed_logins) > 3:
            flash("Too many logins", 'error')
            return redirect("/map")
        username = escape(request.form['username']) or None
        password = request.form['password'] or None
        if username == None or password == None:
            flash("Invalid credentials", 'error')
            return redirect('/map')
        server = Server(identikey_ldap, get_info=ALL, use_ssl=True)
        conn = Connection(server, 'uid={0},ou=Users,{1}'.format(username, identikey_ldap_dc), password)
        conn.bind()    #must be separate or conn throws runtime errors
        result = conn.result
        if result['result'] == 0 and result['description'] == 'success':
            user_in_db = User.query.filter_by(userID=username).first()
            user = User(username)
            conn.search(identikey_ldap_dc, '(uid={})'.format(username), attributes=['*'])
            results = conn.entries
            user.ip_agent = sha256(ip.encode('utf-8') + request.headers.get('User-Agent').encode('utf-8')).hexdigest()
            if len(results) == 1:
                user.displayName = escape(str(results[0]['displayName']))
            print("Login for {} successful".format(username))
            if not(user_in_db):
                db.session.add(user)
            login_user(user)
            login = Login(username, ip, True)
            db.session.add(login)
            db.session.commit()
            return redirect('/manage')
        else:
            print("Login for {0} unsuccessful - {1} [{2}]".format(username, result['description'], result['result']))
            login = Login(username, ip, False)
            db.session.add(login)
            db.session.commit()
            flash("Invalid login")
            base_arr = get_bases()
            return redirect('/login', base_arr=base_arr)
    elif request.method == "GET":
        base_arr = get_bases()
        return render_template("login.html", base_arr=base_arr)

@app.route('/login_dashboard')
@login_required
def login_dashboard():
    if current_user.userID in admins:
        logins_by_user = {}
        logins = Login.query.filter(Login.success == 0).all()
        for login in logins:
            if login.userID in logins_by_user:
                if login.ip in logins_by_user[login.userID]:
                    logins_by_user[login.userID][login.ip] += 1
                else:
                    logins_by_user[login.userID][login.ip] = 1
            else:
                logins_by_user[login.userID] = {login.ip: 1}
        return render_template("login_dashboard.html", logins=logins_by_user)
    else:
        return redirect('/map')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/map')

@app.route('/manage', methods=["GET", "POST"])
@login_required
def manage():
    user = User.query.filter_by(userID=current_user.userID).first()
    base_arr = get_bases()
    friends = Friend.query.order_by(Friend.lname)
    bases = Base.query.order_by(Base.name)
    if request.method == "POST":
        if request.form:
            details = {"name": escape(request.form['name']),
                     "branch": escape(request.form['branch']),
                     "majcom": escape(request.form['majcom']),
                     "lat": escape(request.form['lat']),
                     "lon": escape(request.form['lon'])}
            return render_template("manage.html", friends=friends, bases=bases, details=details, admins=admins, base_arr=base_arr)
        else:
            return render_template("manage.html", friends=friends, bases=bases, admins=admins, base_arr=base_arr)
    else:
        return render_template("manage.html", friends=friends, bases=bases, admins=admins, base_arr=base_arr)

@app.route('/search', methods=["GET", "POST"])
@login_required
def search():
    if request.method == "POST":
        success, details = get_base_info_from_search_string(request.form['base'])
        if success:
            return render_template('manage.html', details=details)
        else:
            flash("Search unsuccessful", 'error')
            return render_template('manage.html')
    elif request.method == "GET":
        return render_template('searchbase.html')

@app.route('/base/<baseID>')
def base(baseID):
    base = Base.query.filter_by(baseID=baseID).first()
    friends_list = Job.query.join(Friend, Job.friendID==Friend.friendID).join(Base, Job.baseID==baseID).add_columns(Friend.fname, Friend.lname, Job.title, Job.start, Job.end, Job.current).filter(Job.current == 1).order_by(Job.start.desc())
    friends = []
    for friend in friends_list:
        friends.append({"fname": escape(friend.fname),
                     "lname": escape(friend.lname),
                     "title": escape(friend.title),
                     "start": escape(format_date(friend.start)),
                     "end": friend.end,
                     "current": friend.current})
    if base.majcom:
        base.majcom = extend_majcom(base.majcom)
    return render_template("display_base.html", base=base, friends=friends)

@app.route('/add_base', methods=["POST"])
@login_required
def add_base():
    if request.method == "POST":
        name = escape(parse_name(request.form['name']))
        city = escape(request.form['city'])
        branch = escape(parse_branch(request.form['branch'])) if request.form.get('branch') else ""
        majcom = escape(parse_majcom(request.form['majcom'])) if request.form.get('majcom') else ""
        try:
            lat = float(request.form['lat'])
            lon = float(request.form['lon'])
        except ValueError:
            flash("Invalid input", 'error')
            return redirect("/manage")
        base_in_db = Base.query.filter_by(name=name).first()
        if not(base_in_db):
            base = Base(name, lat, lon)
            base.city = city
            base.branch = branch
            base.majcom = majcom
            db.session.add(base)
            db.session.commit()
            flash("Base successfully added", 'success')
        else:
            flash("Base already exists", 'error')    
        return redirect("/manage")

@app.route('/edit_base/<baseID>', methods=["GET", "POST"])
@login_required
def edit_base(baseID):
    if request.method == "GET":
        base_arr = get_bases()
        base = Base.query.filter_by(baseID=baseID).first()
        if base:
            return render_template("display_edit_base.html", base=base, base_arr=base_arr)
        else:
            flash("Base not found", 'error')
            return redirect("/manage")
    elif request.method == "POST":
        base = Base.query.filter_by(baseID=baseID).first()
        if base:
            base.name = escape(request.form['name'])
            base.branch = escape(request.form['branch'])
            base.majcom = escape(request.form['majcom'])
            try:
                base.lat = float(request.form['lat'])
                base.lon = float(request.form['lon'])
            except ValueError:
                flash("Invalid input", 'error')
                return redirect("/manage")
            base.descr = escape(request.form['descr'])
            db.session.commit()
            flash("Successfully updated", 'success')
            return redirect("/manage")
        else:
            flash("Base could not be updated", 'error')
            return redirect("/manage")

@app.route('/add_friend', methods=["POST"])
@login_required
def add_friend():
    if request.method == "POST":
        fname = escape(request.form['fname'])
        lname = escape(request.form['lname'])
        friend_in_db = Friend.query.filter_by(fname=fname, lname=lname).first()
        if not(friend_in_db):
            friend = Friend(fname, lname)
            db.session.add(friend)
            db.session.commit()
            flash("Friend successfully added", 'success')
        else:
            flash("Friend already exists", 'error')
        return redirect("/manage")

@app.route('/edit_friend/<friendID>', methods=["GET", "POST"])
@login_required
def edit_friend(friendID):
    if request.method == "GET":
        base_arr = get_bases()
        friend = Friend.query.filter_by(friendID=friendID).first()
        if friend:
            bases = Base.query.order_by(Base.name)
            jobs = Job.query.join(Base, Job.baseID==Base.baseID).add_columns(Job.title, Job.start, Job.end, Job.current, Job.tdy, Base.name).filter(Job.friendID == friendID).order_by(Job.start.desc())
            return render_template("display_edit_friend.html", friend=friend, bases=bases, jobs=jobs, base_arr=base_arr)
        else:
            flash("Friend not found", 'error')
            return redirect("/manage")
    elif request.method == "POST":
        friend = Friend.query.filter_by(friendID=friendID).first()
        if friend:
            friend.fname = escape(request.form['fname'])
            friend.lname = escape(request.form['lname'])
            db.session.commit()
            flash("Successfully updated", 'success')
            return redirect("/manage")
        else:
            flash("Friend could not be updated", 'error')
            return redirect("/manage")
    
@app.route('/add_job', methods=["POST"])
@login_required
def add_job():
    if request.method == "POST":
        try:
            friendID = int(request.form['friendID'])
            baseID = int(request.form['baseID'])
        except ValueError:
            flash("Invalid input", 'error')
            return redirect("/edit_friend/" + friendID)
        title = escape(request.form['title'])
        start = verify_date(request.form['start'])
        end = verify_date(request.form['end'])
        current = True if request.form['current'] == "1" else False
        tdy = True if request.form['tdy'] == "1" else False
        if (start > end or start == "" or end == ""):
            flash("Date error", 'error')
            return redirect("/edit_friend/" + str(friendID))
        else:
            job = Job(title, friendID, baseID, start, end, current, tdy)
            db.session.add(job)
            db.session.commit()
            flash("Job added", 'success')
            return redirect("/edit_friend/" + str(friendID))



if __name__ == '__main__':
    context = ('server.crt', 'server.key')
    app.run(host='0.0.0.0', port=443, threaded=True, ssl_context=context)

#!/usr/bin/python 

from flask import Flask, render_template, request, redirect, session, flash
from flask_login import LoginManager, login_user, logout_user, login_required
from os import urandom
from ldap3 import Server, Connection, ALL
from configparser import ConfigParser

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.secret_key = urandom(12)

cfg = ConfigParser()
cfg.read('settings.cfg')
identikey_ldap = cfg['identikey_ldap']['identikey_ldap']
identikey_ldap_dc = cfg['identikey_ldap']['identikey_ldap_dc']



class User:
	username = ""
	authenticated = "False"
	displayName = ""

	def __init__(self, username):
		self.username = username
		self.displayName = username
	
	def is_authenticated(self):
		return self.authenticated
	
	def is_active(self):
		return True
	
	def is_anonymous(self):
		return False
	
	def get_id(self):
		return self.username

@login_manager.user_loader
def load_user(user_id):
	return User(user_id)

@app.route('/')
def index():
	return render_template("index.html")

@app.route('/map')
def map():
	return render_template("map.html")

@app.route('/login', methods=["GET", "POST"])
def login():
	if request.method == "POST":
		username = request.form['username'] or Null
		password = request.form['password'] or Null
		### Python3 ldap3 connection
		server = Server(identikey_ldap, get_info=ALL, use_ssl=True)
		conn = Connection(server, 'uid={0},ou=Users,{1}'.format(username, identikey_ldap_dc), password)
		conn.bind()	#must be separate or conn throws runtime errors
		result = conn.result
		if result['result'] == 0 and result['description'] == 'success':
			user = User(username)
			login_user(user)
			conn.search(identikey_ldap_dc, '(uid={})'.format(username), attributes=['*'])
			results = conn.entries
			if len(results) == 1:
				user.displayName = str(results[0]['displayName'])
			session['authenticated'] = True
			session['username'] = username
			session['displayName'] = user.displayName
			print("Login for {} successful".format(username))
			return redirect('/')
		else:
			print("Login for {0} unsuccessful - {1} [{2}]".format(username, result['description'], result['result']))
			flash("Invalid login")
			return redirect('/login')
	elif request.method == "GET":
		return render_template("login.html")

@app.route('/logout')
@login_required
def logout():
	if session.get('authenticated'):
		if session['authenticated']:
			session['authenticated'] = False
			session['username'] = ""
	return redirect('/')

@app.route('/manage')
@login_required
def manage():
	if session.get('authenticated'):
		if session['authenticated']:
			return "Success!"
		else:
			return redirect('/login')
	else:
		return redirect('/login')

if __name__ == '__main__':
	context = ('server.crt', 'server.key')
	app.run(host='0.0.0.0', port=443, threaded=True, ssl_context=context)

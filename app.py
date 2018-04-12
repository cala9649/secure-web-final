#!/usr/bin/python 

from flask import Flask, render_template, request, redirect, session, flash
import flask_login
from os import urandom

app = Flask(__name__)
app.secret_key = urandom(12)

@app.route('/')
def index():
	return "Success!"

@app.route('/map')
def map():
	return render_template("map.html")

@app.route('/login', methods=["GET", "POST"])
def login():
	if request.method == "POST":
		username = request.form['username'] or Null
		password = request.form['password'] or Null
		if username == "admin" and password == "password":
			session['authenticated'] = True
			session['username'] = username
			return redirect('/')
		else:
			return "No"
	elif request.method == "GET":
		return render_template("login.html")
		
		 
@app.route('/manage')
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

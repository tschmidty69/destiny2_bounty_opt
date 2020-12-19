from flask import Flask, abort, request, redirect, url_for, render_template, session
from datetime import datetime, timedelta
import os
import pickle
import requests
import requests.auth
import json
from OpenSSL import SSL
import time
from flask_bootstrap import Bootstrap
from Inventory_Management import *
from bounties import *
import urllib
from colorama import init, Fore, Back, Style
#from requests_oauthlib import OAuth2Session


init(autoreset=True)

# initialise the app:
app = Flask(__name__)
app.secret_key = 'Put-your-key-here'
bootstrap = Bootstrap(app)

oauth_session = requests.Session()

# Add you API-KEY-HERE!
API_KEY = os.getenv('API_KEY')
HEADERS = {"X-API-Key": API_KEY }

client_id = '34353'

REDIRECT_URI		=	'https://localhost:5000/callback/bungie'
AUTH_URL			= 	'https://www.bungie.net/en/OAuth/Authorize/?client_id='+client_id+'&response_type=code&'
access_token_url 	=	'https://www.bungie.net/Platform/App/OAuth/token/'
refresh_token_url	=	'https://www.bungie.net/Platform/App/OAuth/token/?client_id='+client_id+'&'
refresh_expires_in  =   datetime.now()

# Open Manifest:
if os.path.isfile("manifest.pickle"):
	print("Opening Manifest...")
	with open('manifest.pickle', 'rb') as data:
		all_data = pickle.load(data)
	print("Finished!")
else:
	print(Fore.RED + "no manifest pickle found")

@app.route('/')
@app.route('/index')
def index():
	state =  make_authorization_url()
	state_params = {'state': state}
	url = AUTH_URL + urllib.parse.urlencode(state_params)
	print("auth url: {}".format(url))
	return render_template('index.html', url=url)


@app.route('/bounties')
def bounties():
	respone = bungie_get(oauth_session, '/User/GetMembershipsForCurrentUser/', '')
	return render_template('bounties.html')


# @app.route('/vault')
# def vault():
# 	userSummary = GetCurrentBungieAccount(oauth_session)
# 	session['destinyMembershipId'] 	= str(userSummary.json()['Response']['destinyAccounts'][0]['userInfo']['membershipId'])
# 	session['membershipType'] 		= str(userSummary.json()['Response']['destinyAccounts'][0]['userInfo']['membershipType'])
# 	session['displayName'] 			= str(userSummary.json()['Response']['destinyAccounts'][0]['userInfo']['displayName'])
# 	vault = getVault(oauth_session, session.get('membershipType'), session.get('destinyMembershipId'))
# 	weaponList = parseVault(oauth_session, vault, all_data)
# 	return render_template('vault.html',
# 							invItems=invItems,
# 							character 		= userSummary.json()['Response']['destinyAccounts'][0]['userInfo']['displayName'],
# 							weaponList=weaponList,
# 							charId 			= userSummary.json()['Response']['destinyAccounts'][0]['characters'][0]['characterId'],
# 							lightLevel 		= userSummary.json()['Response']['destinyAccounts'][0]['characters'][0]['powerLevel'],
# 							emblemImage 	= userSummary.json()['Response']['destinyAccounts'][0]['characters'][0]['emblemPath'],
# 							backgroundImage	= userSummary.json()['Response']['destinyAccounts'][0]['characters'][0]['backgroundPath'],
# 							)

def make_authorization_url():
	# Generate a random string for the state parameter
	# Save it for use later to prevent xsrf attacks
	from uuid import uuid4
	state = str(uuid4())
	save_created_state(state)
	return state

@app.route('/callback/bungie')
def bungie_callback():
	# print(request.__dict__)
	error = request.args.get('error', '')
	if error:
		return "Error: " + error
	state = session.get('state_token')
	if not is_valid_state(state):
		## Uh-oh, this request wasn't started by us!
		print("Uh-oh, this request wasn't started by us!")
		abort(403)
	session.pop('state_token', None)
	code = request.args.get('code')
	token = get_token(code)
	return redirect(url_for('index'))


def format_prepped_request(prepped, encoding=None):
    # prepped has .method, .path_url, .headers and .body attribute to view the request
	encoding = encoding or requests.utils.get_encoding_from_headers(prepped.headers)
	print(prepped.body)
	body = prepped.body.decode(encoding) if encoding else '<binary data>'
	headers = '\n'.join(['{}: {}'.format(*hv) for hv in prepped.headers.items()])
	return f"""\
{prepped.method} {prepped.path_url} HTTP/1.1
{headers}

{body}"""


def get_token(code):
	post_data = {'client_id': client_id, 'grant_type': 'authorization_code', 'code': code}
	url = access_token_url + urllib.parse.urlencode(post_data)
	HEADERS['Content-type']='application/x-www-form-urlencoded'
	#print('HEADERS: {}'.format(HEADERS))
	response = requests.post(access_token_url, data=post_data, headers=HEADERS)
	print("access_token_url: {}".format(url), response, response.content)
	#print(format_prepped_request(response.request, 'utf8'))
	print(response.json())
	try:
		token_json = response.json()['access_token']
		refresh_expires_in = datetime.now() + timedelta(seconds=int(response.json().get('expires_in')))
		save_session(token_json)
	except Exception as e:
		print(Fore.RED + "ERROR\n" + e)
		token_json = ""
		pass
	print('token_json: {}'.format(token_json))
	return token_json

# Update Session:
def save_session(token_json):
	API_KEY = os.getenv('API_KEY')
	print("Updating session ({})".format(API_KEY))
	oauth_session.headers["X-API-Key"] = API_KEY
	oauth_session.headers["Authorization"] = 'Bearer ' + str(token_json)
	access_token = "Bearer " + str(token_json)


# Save state parameter used in CSRF protection:
def save_created_state(state):
	session['state_token'] = state
	pass

def is_valid_state(state):
	saved_state = session['state_token']
	if state == saved_state:
		print("States match, you are who you say you are!")
		return True
	else:
		return False

def refresh_token():
	#TODO
	return

# Main program - call app:
if __name__ == '__main__':
	# User needs to add these:
	context = ('cert.pem', 'key.pem')
	app.run(debug=True, port=5000, ssl_context=context)

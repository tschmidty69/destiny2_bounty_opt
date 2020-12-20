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
import pickle
from colorama import init, Fore, Back, Style
#from requests_oauthlib import OAuth2Session
from config import Config, hashes, hashes_trunc
from forms import *
from zipfile import ZipFile
import sqlite3

init(autoreset=True)

# initialise the app:
app = Flask(__name__)
app.config.from_object(Config)

bootstrap = Bootstrap(app)
oauth_session = requests.Session()

# Add you API-KEY-HERE!
API_KEY = app.config['API_KEY']
HEADERS = {"X-API-Key": API_KEY }

CLIENT_ID = app.config['CLIENT_ID']

REDIRECT_URI        =    'https://localhost:5000/callback/bungie'
AUTH_URL            =     'https://www.bungie.net/en/OAuth/Authorize/?CLIENT_ID='+CLIENT_ID+'&response_type=code&'
access_token_url     =    'https://www.bungie.net/Platform/App/OAuth/token/'
refresh_token_url    =    'https://www.bungie.net/Platform/App/OAuth/token/?CLIENT_ID='+CLIENT_ID+'&'
refresh_expires_in  =   datetime.now()


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
    memberships = []
    bounties = []
    error = ''
    form = select_user()
    refresh_token()
    response = bungie_get(oauth_session, '/User/GetMembershipsForCurrentUser/')
    if response.get('ErrorCode') != 1:
        error = response.get('Message')
    if response.get('Response'):
        memberships = response.get('Response').get('destinyMemberships')
        memberships = reversed(memberships)
        #form.choices = [(member['membershipId'], member['displayName']) for member in memberships]
    # Get Profile with list of characters
    url = "/Destiny2/3/Profile/4611686018497273430/?" + urllib.parse.urlencode({'components': 'characters'})

    # Get Characters with inventory
    response = bungie_get(oauth_session, url)
    url = "/Destiny2/3/Profile/4611686018497273430/Character/2305843009574594606/?" + urllib.parse.urlencode({'components': 'CharacterInventories'})
    response = bungie_get(oauth_session, url)
    for item in response['Response']['inventory']['data']['items']:
        item_data = all_data['DestinyInventoryItemDefinition'][item['itemHash']]['displayProperties']
        if all_data['DestinyInventoryItemDefinition'][item['itemHash']]['itemType'] != 26:
            continue
        else:
            bounties.append(item_data)
        print(item['itemHash'], ": " + item_data['name'] + " - " + item_data['description'] )
    #raise NameError('HiThere')
    return render_template('bounties.html', error=error,
                            form=form, memberships=memberships,
                            bounties=bounties )

# @app.route('/vault')
# def vault():
#     userSummary = GetCurrentBungieAccount(oauth_session)
#     session['destinyMembershipId']     = str(userSummary.json()['Response']['destinyAccounts'][0]['userInfo']['membershipId'])
#     session['membershipType']         = str(userSummary.json()['Response']['destinyAccounts'][0]['userInfo']['membershipType'])
#     session['displayName']             = str(userSummary.json()['Response']['destinyAccounts'][0]['userInfo']['displayName'])
#     vault = getVault(oauth_session, session.get('membershipType'), session.get('destinyMembershipId'))
#     weaponList = parseVault(oauth_session, vault, all_data)
#     return render_template('vault.html',
#                             invItems=invItems,
#                             character         = userSummary.json()['Response']['destinyAccounts'][0]['userInfo']['displayName'],
#                             weaponList=weaponList,
#                             charId             = userSummary.json()['Response']['destinyAccounts'][0]['characters'][0]['characterId'],
#                             lightLevel         = userSummary.json()['Response']['destinyAccounts'][0]['characters'][0]['powerLevel'],
#                             emblemImage     = userSummary.json()['Response']['destinyAccounts'][0]['characters'][0]['emblemPath'],
#                             backgroundImage    = userSummary.json()['Response']['destinyAccounts'][0]['characters'][0]['backgroundPath'],
#                             )

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
    print("session", session)
    code = request.args.get('code')
    token = get_token(code)
    return redirect(url_for('bounties'))


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
    post_data = {'CLIENT_ID': CLIENT_ID, 'grant_type': 'authorization_code', 'code': code}
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
        save_session(token_json, refresh_expires_in)
    except Exception as e:
        print(e)
        token_json = ""
        pass
    print('token_json: {}'.format(token_json))
    return token_json

# Update Session:
def save_session(token_json, refresh_expires_in):
    print("Updating session")
    oauth_session.headers["X-API-Key"] = API_KEY
    oauth_session.headers["Authorization"] = 'Bearer ' + str(token_json)
    session['token_json']=token_json
    session['refresh_expires_in']=refresh_expires_in

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
    print("token_json", session['token_json'])
    print("refresh_expires_in", session['refresh_expires_in'])
    print("now               ", datetime.now())
    expiring = session['refresh_expires_in'] - datetime.now()
    print("expiring: ",  expiring.seconds/60, expiring.seconds)
    oauth_session.headers["X-API-Key"] = API_KEY
    oauth_session.headers["Authorization"] = 'Bearer ' + str(session['token_json'])

    return

# @app.before_first_request
def build_dict():
    global all_data
    hashes = {'DestinyInventoryItemDefinition': 'hash'}
    #connect to the manifest
    con = sqlite3.connect('manifest.content')
    print('Connected')
    #create a cursor object
    cur = con.cursor()

    all_data = {}
    #for every table name in the dictionary
    for table_name in hashes.keys():
        #get a list of all the jsons from the table
        cur.execute('SELECT json from '+table_name)
        print('Generating '+table_name+' dictionary....')

        #this returns a list of tuples: the first item in each tuple is our json
        items = cur.fetchall()

        #create a list of jsons
        item_jsons = [json.loads(item[0]) for item in items]

        #create a dictionary with the hashes as keys
        #and the jsons as values
        item_dict = {}
        hash = hashes[table_name]
        for item in item_jsons:
            item_dict[item[hash]] = item

        #add that dictionary to our all_data using the name of the table
        #as a key.
        all_data[table_name] = item_dict

    print('Dictionary Generated!')
    return

def load_pickle():
    #check if pickle exists, if not create one.
    if os.path.isfile(r'path\to\file\manifest.content') == False:
        get_manifest()
        all_data = build_dict(hashes)
        with open('manifest.pickle', 'wb') as data:
            pickle.dump(all_data, data)
            print("'manifest.pickle' created!\nDONE!")
    else:
        print('Pickle Exists')

    with open('manifest.pickle', 'rb') as data:
        all_data = pickle.load(data)


@app.before_first_request
def get_manifest():
    # Check if manifest.pickle is up to date
    # else get zip file
    # unzip file
    # build Dictionary
    # save pickle
    cachefile = 'manifest.zip'
    if os.path.isfile(cachefile):
        creation_time = os.path.getctime(cachefile)
        if (time.time() - creation_time) // (86400) >= 1:
            os.unlink(cachefile)
            print("removing cached result from '%s' (older than 1 day)" % cachefile)
        else:
            print("found manifest file")
    else:
        print("no manifest file found, trying to download")
        response = requests.get('https://www.bungie.net/Platform/Destiny2/Manifest/',
                                headers=HEADERS)
        print(HEADERS, response.json())
        if response.json():
            url = response.json()['Response']['mobileWorldContentPaths']['en']
            print("manifest_url: https://www.bungie.net" + url)
            response = requests.get("https://www.bungie.net" + url, headers=HEADERS)
            with open(cachefile, 'wb') as cachehandle:
                print("saving result to cache '%s'" % cachefile)
                cachehandle.write(response.content)
    with ZipFile('manifest.zip') as zip:
        name = zip.namelist()
        zip.extractall()
    try:
        os.rename(name[0], 'manifest.content')
    except:
        pass
    print('Unzipped!')
    build_dict()
    return


# Main program - call app:
if __name__ == '__main__':
    # User needs to add these:
    context = ('cert.pem', 'key.pem')
    app.run(debug=True, port=5000, ssl_context=context)

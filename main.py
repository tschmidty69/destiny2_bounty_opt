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
# from bounties import *
import urllib
import pickle
#from colorama import init, Fore, Back, Style
#from requests_oauthlib import OAuth2Session
from config import *
#from forms import *
from zipfile import ZipFile
import sqlite3
from flask_wtf.csrf import CSRFProtect

# colorama
#init(autoreset=True)

from logging.config import dictConfig

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

# initialise the app:
app = Flask(__name__)
app.config.from_object(Config)

bootstrap = Bootstrap(app)
csrf = CSRFProtect(app)
oauth_session = requests.Session()
destiny_data = {}

# Add you API-KEY-HERE!
API_KEY = app.config['API_KEY']
HEADERS = {"X-API-Key": API_KEY }

CLIENT_ID = app.config['CLIENT_ID']

REDIRECT_URI        =    'https://localhost:5000/callback/bungie'
AUTH_URL            =     'https://www.bungie.net/en/OAuth/Authorize/?CLIENT_ID='+CLIENT_ID+'&response_type=code&'
access_token_url     =    'https://www.bungie.net/Platform/App/OAuth/token/'
refresh_token_url    =    'https://www.bungie.net/Platform/App/OAuth/token/?CLIENT_ID='+CLIENT_ID+'&'
# URL Builder:
base_url = "https://www.bungie.net/platform/"


def cached(cachefile, ttl=86400):
    """
    A function that creates a decorator which will use "cachefile" for caching the results of the decorated function "fn".
    """
    def decorator(fn):  # define a decorator for a function "fn"
        def wrapped(*args, **kwargs):   # define a wrapper that will finally call "fn" with all arguments
            if os.path.exists(cachefile):
               creation_time = os.path.getctime(cachefile)
               # 86400 is one day
               if (time.time() - creation_time) // (ttl) >= 1:
                   os.unlink(cachefile)
                   app.logger.info("removing cached result from '%s' (older than %s hours)" % cachefile, ttl/3600)

            # if cache exists -> load it and return its content
            if os.path.exists(cachefile):
                with open(cachefile, 'rb') as cachehandle:
                    app.logger.info("using cached result from '%s'" % cachefile)
                    return pickle.load(cachehandle)

            # execute the function with all arguments passed
            res = fn(*args, **kwargs)

            # write to cache file
            with open(cachefile, 'wb') as cachehandle:
                app.logger.info("saving result to cache '%s'" % cachefile)
                pickle.dump(res, cachehandle)

            return res

        return wrapped

    return decorator


@app.route('/')
@app.route('/index')
def index():
    global page_data
    state =  make_authorization_url()
    state_params = {'state': state}
    url = AUTH_URL + urllib.parse.urlencode(state_params)
    app.logger.info("auth url: {}".format(url))
    return render_template('index.html', url=url)


@app.route('/bounties', methods=['GET', 'POST'])
def bounties():
    memberships = []
    characters = []
    bounties = []
    error = ''
    global destiny_data
    if not session.get('profile'):
        session['profile'] = {}
    if not session.get('character'):
        session['character'] = {}
    if not session.get('characters'):
        session['characters'] = []


    # global page_data
    if not destiny_data:
        destiny_data = build_dict()

    # Good god this is clunky
    if request.method == 'POST':
        app.logger.info('POST: %s', request.form)
        if request.form.get('profile'):
            formatted = (request.form['profile'].replace("'", "\"")).replace('True', 'true')
            app.logger.info("saving profile: %s", formatted)
            session['profile'] = json.loads(formatted)
        if request.form.get('character'):
            formatted = (request.form['character'].replace("'", "\"")).replace('True', 'true')
            app.logger.info("saving character: %s", formatted)
            app.logger.info("saving session: %s", formatted)
            session['character'] = json.loads(formatted)


    if not 'displayName' in session.get('profile'):
        # Get membership with profile id
        response = bungie_get(oauth_session, '/User/GetMembershipsForCurrentUser/')
        if response.get('ErrorCode') != 1:
            error = response.get('Message')
        if response.get('Response'):
            memberships = response.get('Response').get('destinyMemberships')
            memberships = reversed(memberships)
    elif 'characterId' in session.get('character'):
        fetch_character_items()
    else:
        fetch_characters()

    return render_template('bounties.html', error=error,
                            memberships=memberships,
                            class_names=class_names)


def fetch_character_items():
    app.logger.info("session['character']: %s: %s", type(session['character']), session['character'])
    # Get Characters with inventory
    session['bounties'] = []
    url = ("/Destiny2/" + str(session['profile']['membershipType']) + "/Profile/" +
           str(session['profile']['membershipId']) + "/Character/" +
           str(session['character']['characterId']) + "/?" +
           urllib.parse.urlencode({'components': 'CharacterInventories'}))
    #url = "/Destiny2/3/Profile/4611686018497273430/Character/2305843009574594606/?" + urllib.parse.urlencode({'components': 'CharacterInventories'})
    response = bungie_get(oauth_session, url)
    for item in response['Response']['inventory']['data']['items']:
        item_data = destiny_data['DestinyInventoryItemDefinition'][item['itemHash']]['displayProperties']
        if destiny_data['DestinyInventoryItemDefinition'][item['itemHash']]['itemType'] != 26:
            continue
        else:
            item_data['itemHash'] = item['itemHash']
            session['bounties'].append(item_data)
        # endid
        app.logger.info("%s\t: %s - %s", item['itemHash'], item_data['name'], item_data['description'] )
    classify_bounties()
    return


def fetch_characters():
    session['characters'] = []
    app.logger.info("fetch_characters()")
    app.logger.info("session['characters']: %s: %s", type(session['characters']), session['characters'])

    # Get Profile with list of characters
    url = ("/Destiny2/" + str(session['profile']['membershipType']) +
           "/Profile/" + str(session['profile']['membershipId']) + "/?" +
           urllib.parse.urlencode({'components': 'characters'}))
    response = bungie_get(oauth_session, url)
    # app.logger.info("%s: %s", response, json.dumps(response, indent=1))
    for character in response.get('Response').get('characters').get('data'):
        url = ("/Destiny2/" + str(session['profile']['membershipType']) + "/Profile/" +
               str(session['profile']['membershipId']) + "/Character/" +
               str(character) + "/?" +
               urllib.parse.urlencode({'components': 'Characters'}))
        response = bungie_get(oauth_session, url)
        # app.logger.info("%s: %s", response, json.dumps(response, indent=1))
        session['characters'].append(response.get('Response').get('character').get('data'))
    app.logger.info("session['characters']: %s: %s", type(session['characters']), session['characters'])


def classify_bounties():
    bounty_classed = {}
    # test = {'location': [],
    #                   'activity': [],
    #                   'element': [],
    #                   'precision': [],
    #                   'finisher': [],
    #                   'enemy-race': [],
    #                   'enemy-type': []
    #                   }
    for bounty in session.get('bounties'):
        bounty_classed[bounty['itemHash']] = {}
        for location in locations:
            if location in bounty['description']:
                # TODO CONVERT TO REDIS
                bounty_classed[bounty['itemHash']]['location']=location
    print(bounty_classed)
    return

@app.route('/callback/bungie')
def bungie_callback():
    # app.logger.info(request.__dict__)
    error = request.args.get('error', '')
    if error:
        return "Error: " + error
    state = session.get('state_token')
    if not is_valid_state(state):
        ## Uh-oh, this request wasn't started by us!
        app.logger.error("Uh-oh, this request wasn't started by us!")
        abort(403)
    session.pop('state_token', None)
    app.logger.info("session: %s", session)
    code = request.args.get('code')
    session['code'] = code
    get_token(code)
    return redirect(url_for('bounties'))


def bungie_get(oauth_session, path):
    refresh_token()
    url = base_url + path
    app.logger.info("bungie_get url: {}".format(url))
    # app.logger.info('bungie_get headers:  {}'.format(oauth_session.headers))
    response = oauth_session.get(url)
    # app.logger.info(response, json.dumps(response.json(), indent=1))
    # TODO: Check for errors
    return response.json()


def make_authorization_url():
    # Generate a random string for the state parameter
    # Save it for use later to prevent xsrf attacks
    from uuid import uuid4
    state = str(uuid4())
    save_created_state(state)
    return state


def get_token(code):
    post_data = {'CLIENT_ID': CLIENT_ID, 'grant_type': 'authorization_code', 'code': code}
    url = access_token_url + urllib.parse.urlencode(post_data)
    HEADERS['Content-type']='application/x-www-form-urlencoded'
    #app.logger.info('HEADERS: {}'.format(HEADERS))
    response = requests.post(access_token_url, data=post_data, headers=HEADERS)
    app.logger.info("access_token_url: %s", url)
    # app.logger.debug("response: %s %s", response, response.content)
    try:
        token_json = response.json()['access_token']
        refresh_expires_in = datetime.now() + timedelta(seconds=int(response.json().get('expires_in')))
        save_session(code, token_json, refresh_expires_in)
    except Exception as e:
        app.logger.info(e)
        token_json = ""
        pass

    # app.logger.info('token_json: {}'.format(token_json))
    return


def refresh_token():
    #app.logger.debug("token_json       : %s", session['token_json'])
    app.logger.info("refresh_expires_in: %s", session['refresh_expires_in'])
    #app.logger.info("now               : %s", datetime.now())
    expiring = session['refresh_expires_in'] - datetime.now()
    #expires = datetime.strptime(session['refresh_expires_in'], '%Y-%m-%d %H:%M:%S.%f')
    if datetime.now() > session['refresh_expires_in']:
        app.logger.info("expired: %s seconds",  expiring.seconds)
        code = session['code']
        post_data = {'CLIENT_ID': CLIENT_ID, 'grant_type': 'refresh_token',
                     'refresh_token': session['token_json']}
        url = access_token_url + urllib.parse.urlencode(post_data)
        HEADERS['Content-type']='application/x-www-form-urlencoded'
        #app.logger.info('HEADERS: {}'.format(HEADERS))
        response = requests.post(access_token_url, data=post_data, headers=HEADERS)
        app.logger.info("access_token_url: %s", url)
        # app.logger.debug("response: %s %s", response, response.content)
        try:
            token_json = response.json()['access_token']
            refresh_expires_in = datetime.now() + timedelta(seconds=int(response.json().get('expires_in')))
            save_session(code, token_json, refresh_expires_in)
        except Exception as e:
            app.logger.info(e)
            token_json = ""
            pass
        # app.logger.info('token_json: {}'.format(token_json))
    else:
        app.logger.info("expiring in: %s minutes",  expiring.seconds/60)

    oauth_session.headers["X-API-Key"] = API_KEY
    oauth_session.headers["Authorization"] = 'Bearer ' + str(session['token_json'])
    return


def save_session(code, token_json, refresh_expires_in):
    app.logger.info("saving session")
    oauth_session.headers["X-API-Key"] = API_KEY
    oauth_session.headers["Authorization"] = 'Bearer ' + str(token_json)
    session['token_json']=token_json
    session['refresh_expires_in']=refresh_expires_in
    # access_token = "Bearer " + str(token_json)


# Save state parameter used in CSRF protection:
def save_created_state(state):
    session['state_token'] = state
    pass


def is_valid_state(state):
    saved_state = session['state_token']
    if state == saved_state:
        app.logger.info("States match, you are who you say you are!")
        return True
    else:
        return False


# @app.before_first_request
@cached('build_dict.pickle')
def build_dict():
    hashes = hashes_trunc
    #connect to the manifest
    con = sqlite3.connect('manifest.content')
    app.logger.info('Connected')
    #create a cursor object
    cur = con.cursor()

    all_data = {}
    #for every table name in the dictionary
    for table_name in hashes.keys():
        #get a list of all the jsons from the table
        cur.execute('SELECT json from '+table_name)
        app.logger.info('Generating '+table_name+' dictionary....')

        #this returns a list of tuples: the first item in each tuple is our json
        items = cur.fetchall()

        # create a list of jsons
        # item[0]['hash'], item[0]['name'], item[0]['description']
        # hacked this to only pull certain keys to save memory for heroku
        items_json = []
        for item in items:
            # print("item", type(item[0]), item[0])
            item_json = json.loads(item[0])
            # if item_json.get('itemType') == 26:
            # print("loading", item_json['displayProperties']['name'], ":",
            #       item_json['displayProperties']['description'])
            items_json.append({'hash': item_json['hash'],
                               'itemType': item_json['itemType'],
                               'displayProperties': item_json['displayProperties']})


        # items_json = [json.loads(item[0]) for item in items]

        #create a dictionary with the hashes as keys
        #and the jsons as values
        item_dict = {}
        hash = hashes[table_name]
        for item in items_json:
            item_dict[item[hash]] = item

        #add that dictionary to our all_data using the name of the table
        #as a key.
        all_data[table_name] = item_dict

    app.logger.info('Dictionary Generated!')
    con.close()
    return all_data


@app.before_first_request
def get_manifest():
    # Check if manifest.zip is up to date
    # else get zip file
    # unzip file
    # build Dictionary
    # save pickle
    zipfile = 'manifest.zip'
    contentfile = 'manifest.content'
    if os.path.isfile(zipfile):
        creation_time = os.path.getctime(zipfile)
        if (time.time() - creation_time) // (86400) >= 1:
            os.unlink(zipfile)
            app.logger.info("removing cached result: '%s' (older than 1 day)" % zipfile)
        else:
            app.logger.info("using cached result: '%s'" % zipfile)
    if os.path.isfile(contentfile):
        creation_time = os.path.getctime(contentfile)
        if (time.time() - creation_time) // (86400) >= 1:
            os.unlink(contentfile)
            app.logger.info("removing cached result: '%s' (older than 1 day)" % contentfile)
        else:
            app.logger.info("using cached result: '%s'" % contentfile)

    if os.path.isfile(zipfile):
        try:
            with ZipFile(zipfile) as zip:
                name = zip.namelist()
                app.logger.info("found %s file containing %s", zipfile, name[0])
        except:
            app.logger.error("error loading %s, deleting", zipfile)
            os.unlink(zipfile)
            app.logger.info('deleted %s', zipfile)
    else:
        app.logger.info("no manifest file found, trying to download")
        response = requests.get('https://www.bungie.net/Platform/Destiny2/Manifest/',
                                headers=HEADERS)
        app.logger.info(HEADERS, response.json())
        if response.json():
            url = response.json()['Response']['mobileWorldContentPaths']['en']
            app.logger.info("manifest_url: https://www.bungie.net" + url)
            response = requests.get("https://www.bungie.net" + url, headers=HEADERS)
            with open(zipfile, 'wb') as cachehandle:
                app.logger.info("saving result to '%s'" % zipfile)
                cachehandle.write(response.content)
    if not os.path.isfile(contentfile):
        extract_manifest_zip(zipfile)
    destiny_data = build_dict()

def extract_manifest_zip(zipfile):
    with ZipFile(zipfile) as zip:
        name = zip.namelist()
        zip.extractall()
        app.logger.info('unzipped %s', zipfile)
    try:
        os.unlink('manifest.content')
        app.logger.info('deleted manifest.content')
    except:
        pass
    try:
        os.rename(name[0], 'manifest.content')
        app.logger.info('renamed %s to manifest.content', zipfile)
    except:
        app.logger.error('error renaming %s to manifest.content', zipfile)
    try:
        os.unlink(name[0])
        app.logger.info('deleted %s', name[0])
    except:
        app.logger.error('error deleting %s', name[0])
    return


# Main program - call app:
if __name__ == '__main__':
    # User needs to add these:
    context = ('cert.pem', 'key.pem')

    app.run(debug=True, port=5000, ssl_context=context)

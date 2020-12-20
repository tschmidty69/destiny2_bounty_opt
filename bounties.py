from flask import session
import requests
import json

# URL Builder:
base_url = "https://www.bungie.net/platform/"

def bungie_get(oauth_session, path):
    url = base_url + path
    print("bungie_get url: {}".format(url))
    print('bungie_get headers:  {}'.format(oauth_session.headers))
    response = oauth_session.get(url)
    print(response, json.dumps(response.json(), indent=1))
    return response.json()

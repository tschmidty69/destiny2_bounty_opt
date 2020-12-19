import requests
import json

# URL Builder:
base_url = "https://www.bungie.net/platform/"

def bungie_get(oauth_session, path, data):
    url = base_url + path
    print("request url: {}".format(url))
    print('HEADERS:  {}'.format(oauth_session.headers))
    res = oauth_session.get(url)
    print(res, json.dumps(res.json(), indent=1))
    #try:
    #    membership_id = res.json().'Response']['bungieNetUser']['membershipId']
    #error_stat = res.json()['ErrorStatus'].decode('utf-8')
    #print("Error status: " + error_stat + "\n")
    return res

import os
from flask import Flask, g, session, redirect, request, url_for, jsonify, abort
from requests_oauthlib import OAuth2Session
import requests
import sqlite3

import time

from hashlib import sha256

DB_PATH = '/opt/app/db/users.db'

OAUTH2_CLIENT_ID = os.environ['OAUTH2_CLIENT_ID']
OAUTH2_CLIENT_SECRET = os.environ['OAUTH2_CLIENT_SECRET']
OAUTH2_REDIRECT_URI = os.environ['JOINER_BASE_URL'] + '/callback'

FAILED_JOIN_URL = os.environ.get('FAILED_JOIN_URL', '')
API_BASE_URL = os.environ.get('API_BASE_URL', 'https://discord.com/api')
AUTHORIZATION_BASE_URL = API_BASE_URL + '/oauth2/authorize'
TOKEN_URL = API_BASE_URL + '/oauth2/token'

BOT_TOKEN = os.environ['BOT_TOKEN']
GUILD_ID = os.environ['GUILD_ID']
LINK_SECRET = os.environ['URL_SECRET']
FETCH_SECRET = os.environ['FETCH_SECRET']

app = Flask(__name__)
app.debug = False
app.config['SECRET_KEY'] = OAUTH2_CLIENT_SECRET

if 'http://' in OAUTH2_REDIRECT_URI:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'

def token_updater(token):
    session['oauth2_token'] = token


def make_session(token=None, state=None, scope=None):
    return OAuth2Session(
        client_id=OAUTH2_CLIENT_ID,
        token=token,
        state=state,
        scope=scope,
        redirect_uri=OAUTH2_REDIRECT_URI,
        auto_refresh_kwargs={
            'client_id': OAUTH2_CLIENT_ID,
            'client_secret': OAUTH2_CLIENT_SECRET,
        },
        auto_refresh_url=TOKEN_URL,
        token_updater=token_updater)


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
    return db

@app.teardown_appcontext
def close_connection(excpetion):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/ids')
def ids():
    id = request.args.get('user_id', None)
    auth = request.args.get('hash', None)
    if not id or not auth:
        abort(400)
    auth_string = "{} {}".format(id, FETCH_SECRET).encode('utf-8')
    if sha256(auth_string).hexdigest() != auth:
        abort(403)
    cur = get_db().cursor()
    cur.execute('SELECT discord_id FROM discord_names WHERE user_id = ?', (id,))
    results = cur.fetchall()
    results = [x[0] for x in results]
    return jsonify(ids=results)

@app.route('/e6ids')
def e6ids():
    id = request.args.get('discord_id', None)
    auth = request.args.get('hash', None)
    if not id or not auth:
        abort(403)
    auth_string = "{} {}".format(id, FETCH_SECRET).encode('utf-8')
    if sha256(auth_string).hexdigest() != auth:
        abort(403)
    cur = get_db().cursor()
    cur.execute('SELECT user_id FROM discord_names WHERE discord_id = ?', (id,))
    results = cur.fetchall()
    results = [x[0] for x in results]
    return jsonify(ids=results)

@app.route('/')
def index():
    username = request.args.get('username', None)
    user_id = request.args.get('user_id', None)
    t2 = request.args.get('time', None)
    auth = request.args.get('hash', None)
    if not username or not user_id or not auth or not t2:
        abort(400)
    print(int(t2), int(time.time()))
    if int(time.time()) > int(t2):
        print("time has expired")
        abort(403)
    auth_string = "{} {} {} {}".format(username, user_id, t2, LINK_SECRET).encode('utf-8')
    if sha256(auth_string).hexdigest() != auth:
        print('bad auth {} {}'.format(auth, sha256(auth_string).hexdigest()))
        abort(403)
    session['username'] = username
    session['user_id'] = user_id
    discord = make_session(scope=['identify', 'guilds.join'])
    authorization_url, state = discord.authorization_url(AUTHORIZATION_BASE_URL)
    session['oauth2_state'] = state
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    if request.values.get('error'):
        return request.values['error']
    discord = make_session(state=session.get('oauth2_state'))
    token = discord.fetch_token(
        TOKEN_URL,
        client_secret=OAUTH2_CLIENT_SECRET,
        authorization_response=request.url)
    session['oauth2_token'] = token
    return redirect(url_for('.join'))


@app.route('/me')
def me():
    discord = make_session(token=session.get('oauth2_token'))
    user = discord.get(API_BASE_URL + '/users/@me').json()
    return jsonify(user=user)

@app.route('/join')
def join():
    token = session.get('oauth2_token')
    if not token:
        abort(403)
    if 'username' not in session:
        abort(403)
    if 'user_id' not in session:
        abort(403)
    discord = make_session(token=session.get('oauth2_token'))
    user = discord.get(API_BASE_URL + '/users/@me').json()
    if 'error' in user:
        session.clear()
        print(user)
        abort(403)

    new_username = session.get('username').replace('_', ' ')
    cur = get_db().cursor()
    d_username = user['username'] + '#' + user['discriminator']
    cur.execute('INSERT INTO discord_names(user_id, discord_id, discord_username) VALUES (?, ?, ?)', (session['user_id'], user['id'], d_username))
    join = requests.put(f"{API_BASE_URL}/guilds/{GUILD_ID}/members/{user['id']}",
                 headers={'Authorization': f'Bot {BOT_TOKEN}',
                          'Contet-Type': 'application/json'},
                 json={'access_token': discord.access_token,
                       'nick': new_username})

    print("Status code: %d" % join.status_code)
    if join.status_code not in [200, 201, 204]:
        print("WAT!?")
        print(join.text)
        if FAILED_JOIN_URL:
            requests.post(FAILED_JOIN_URL, headers={'Content-Type': 'application/json'},
                json={'content': f"https://e621.net/users/{session['user_id']} tried to join as {user['id']}:{d_username} and got `{join.text}`"})
        session.clear()
        abort(403)
    session.clear()
    get_db().commit()
    return "You have been joined to the server."

if __name__ == '__main__':
    app.run()

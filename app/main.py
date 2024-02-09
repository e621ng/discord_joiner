import os
from flask import Flask, g, session, redirect, request, url_for, jsonify, abort, render_template
from requests_oauthlib import OAuth2Session
import requests
import sqlite3
import math

import time

from hashlib import sha256

DB_PATH = '/opt/app/data/users.db'
DB_SCHEMA = '''
    CREATE TABLE IF NOT EXISTS discord_names (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        discord_id VARCHAR(128) NOT NULL,
        discord_username VARCHAR(128) NOT NULL,
        added_on datetime NOT NULL DEFAULT (datetime('now', 'localtime'))
    )
'''

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

with app.app_context():
    db = get_db()
    db.cursor().execute(DB_SCHEMA)

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
    cur.execute('SELECT DISTINCT discord_id FROM discord_names WHERE user_id = ?', (id,))
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
    cur.execute('SELECT DISTINCT user_id FROM discord_names WHERE discord_id = ?', (id,))
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
    if int(time.time()) > int(t2):
        abort(403, f'You took too long to authorize the request. Please try again.')
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
        abort(400, request.values.get('error'))
    if 'oauth2_state' not in session:
        abort(403)

    discord = make_session(state=session.get('oauth2_state'))
    token = discord.fetch_token(
        TOKEN_URL,
        client_secret=OAUTH2_CLIENT_SECRET,
        authorization_response=request.url)
    session['oauth2_token'] = token
    return redirect(url_for('.join'))

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
    if user['discriminator'] == '0':
        d_username = user['username']
    else:
        d_username = user['username'] + '#' + user['discriminator']

    cur.execute('INSERT INTO discord_names(user_id, discord_id, discord_username) VALUES (?, ?, ?)', (session['user_id'], user['id'], d_username))
    get_db().commit()
    join = requests.put(f"{API_BASE_URL}/guilds/{GUILD_ID}/members/{user['id']}",
                 headers={'Authorization': f'Bot {BOT_TOKEN}',
                          'Contet-Type': 'application/json'},
                 json={'access_token': discord.access_token,
                       'nick': new_username})

    revoke = requests.post(f'{API_BASE_URL}/oauth2/token/revoke', headers={'Content-Type': 'application/x-www-form-urlencoded'},
                data={'client_id': OAUTH2_CLIENT_ID, 'client_secret': OAUTH2_CLIENT_SECRET, 'token': discord.access_token})
    if revoke.status_code not in [200, 201, 204]:
        print(f"Failed to revoke token: {response.status} {response.text}")

    if join.status_code not in [200, 201, 204]:
        created_at = math.floor(((int(user['id']) >> 22) + 1420070400000) / 1000)
        requests.post(FAILED_JOIN_URL, headers={'Content-Type': 'application/json'},
            json={'content': f"https://e621.net/users/{session['user_id']} tried to join as {user['id']}:{d_username} (<t:{created_at}:d>) and got `{join.text}`"})
        session.clear()
        response = join.json()
        abort(403, friendly_discord_error(response['code']))

    session.clear()
    return render_template('page.html', title='Success', message=f'You have been added to the server. <a href="https://discord.com/channels/{GUILD_ID}">See you there.</a>'), 200

def friendly_discord_error(code):
    # https://discord.com/developers/docs/topics/opcodes-and-status-codes#json
    match code:
        case 30001:
            return 'You are at the discord server limit. Try again after you have left some servers.'
        case 40069:
            return 'Invites for our discord server are currently disabled. Try again at a later date.'
        case 40007:
            return 'You are either IP banned by discord (are you using a VPN?) or banned from the server. Server bans may be appealed by writing an email to management@e621.net.'
        case 20024:
            return 'Could not add you to the server. Make sure you are able to access other NSFW-marked servers on your discord client.'
        case _:
            return 'An unknown error occurred.'

@app.errorhandler(400)
def bad_request(message):
    return render_template('page.html', title='Bad Request', message=str(message)), 400

@app.errorhandler(403)
def forbidden(message):
    return render_template('page.html', title='Forbidden', message=str(message)), 403

@app.errorhandler(404)
def not_found(message):
    return render_template('page.html', title='Not Found', message=str(message)), 404

if __name__ == '__main__':
    app.run()

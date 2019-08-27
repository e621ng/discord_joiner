import sqlite3

db = sqlite3.connect('initial.db')

cur = db.cursor()
cur.execute('''CREATE TABLE discord_names (
 id INTEGER PRIMARY KEY,
 user_id INTEGER NOT NULL,
 discord_id VARCHAR(128) NOT NULL,
 discord_username VARCHAR(128) NOT NULL,
 added_on datetime NOT NULL DEFAULT (datetime('now', 'localtime')))''')
cur.commit()

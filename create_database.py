import sqlite3

# Connect to the database and create the users table if it doesn't exist
connection = sqlite3.connect('database.db')
cursor = connection.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL
)
''')

connection.commit()
connection.close()

print("Database and users table created successfully.")

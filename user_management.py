import sqlite3 as sql
import time
import random
import pyotp


def insertUser(username, password, DoB):
    """
    Insert a new user into the database with username, password, date of birth, and a unique 2FA key.
    """
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    key = pyotp.random_base32()  # Generate the 2FA key

    # Use double quotes for "2FA_Key" due to special characters
    cur.execute(
        'INSERT INTO users (username, password, dateOfBirth, "2FA_Key") VALUES (?, ?, ?, ?)',
        (username, password, DoB, key),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password, otp=None):
    """
    Retrieve a user from the database by username and password.
    Return a tuple (isLoggedIn, twoFA_Key) and optionally verify the OTP if provided.
    """
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Fetch user by username and password
    cur.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cur.fetchone()

    if user is None:  # Username or password mismatch
        con.close()
        return False, None

    # Fetch the user's 2FA key from the record
    twoFA_Key = user[-1]  # Assuming "2FA_Key" is the last column in the table

    if otp:
        # Validate the OTP if provided
        totp = pyotp.TOTP(twoFA_Key)
        if not totp.verify(otp):  # OTP is invalid
            con.close()
            return False, None

    # Increment visitor count
    _increment_visitor_log()

    con.close()
    return True, twoFA_Key  # Return login status and 2FA key




def get_2fa_key(username):
    """
    Retrieve the 2FA secret key for a specific user.
    """
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Safeguard with parameterized query
    cur.execute('SELECT "2FA_Key" FROM users WHERE username = ?', (username,))
    result = cur.fetchone()

    con.close()
    return result[0] if result else None


def _increment_visitor_log():
    """
    Increment the visitor count in a log file.
    """
    try:
        with open("visitor_log.txt", "r") as file:
            number = int(file.read().strip())
    except (FileNotFoundError, ValueError):
        number = 0  # Start the counter if the file doesn't exist or is invalid

    number += 1
    with open("visitor_log.txt", "w") as file:
        file.write(str(number))
    time.sleep(random.randint(80, 90) / 1000)  # Simulate delay


def insertFeedback(feedback):
    """
    Insert feedback into the database.
    """
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
    con.commit()
    con.close()


def listFeedback():
    """
    Fetch all feedback from the database and write it to a partial HTML file.
    """
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()

    # Writing feedback to success_feedback.html
    with open("templates/partials/success_feedback.html", "w") as f:
        for row in data:
            f.write("<p>\n")
            f.write(f"{row[1]}\n")  # Assuming the second column holds feedback text
            f.write("</p>\n")
import sqlite3 as sql
import time
import random
import pyotp
import bcrypt
import html


def insertUser(username, password, DoB):
    """
    Insert a new user into the database safely using transactions.
    """
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    key = pyotp.random_base32()  # Generate the 2FA key

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    try:
        con.execute("BEGIN TRANSACTION;")

        # Ensure username does not already exist (atomic check)
        cur.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            raise ValueError("Username already exists!")

        # Insert new user
        cur.execute(
            'INSERT INTO users (username, password, dateOfBirth, "two_factor_key") VALUES (?, ?, ?, ?)',
            (username, hashed_password, DoB, key),
        )

        con.commit()  # Commit only if everything is successful
    except sql.IntegrityError:
        con.rollback()
        raise ValueError("Duplicate username detected!")
    finally:
        con.close()



def retrieveUsers(username, password, otp=None):
    """
    Retrieve user from the database and prevent simultaneous authentication issues.
    """
    time.sleep(random.randint(50, 200) / 1000)  # Random delay to reduce Side Channel Attack possibility
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    try:
        con.execute("BEGIN TRANSACTION;")
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if user is None:
            return None

        stored_hashed_password = user[2]

        if not bcrypt.checkpw(password.encode("utf-8"), stored_hashed_password.encode("utf-8")):
            return None

        con.commit()
        return user
    except Exception as oops:
        print("Error checking password: ",oops)
        con.rollback()
        return None
    finally:
        con.close()



def _increment_visitor_log():
    """
    Increment the visitor count in a log file safely.
    """
    try:
        with open("visitor_log.txt", "r+") as file:
            fcntl.flock(file, fcntl.LOCK_EX)  # Acquire an exclusive lock

            try:
                number = int(file.read().strip())  # Read current count
            except ValueError:
                number = 0

            number += 1
            file.seek(0)
            file.write(str(number))
            file.truncate()  # Ensure old content is removed

            time.sleep(random.randint(80, 90) / 1000)  # Simulate delay

            fcntl.flock(file, fcntl.LOCK_UN)  # Release the lock
    except FileNotFoundError:
        with open("visitor_log.txt", "w") as file:
            file.write("1")  # Initialize file if it doesn’t exist




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
            f.write(html.escape(row[1]))  # Assuming the second column holds feedback text
            f.write("</p>\n")
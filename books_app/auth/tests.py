import os
from unittest import TestCase
import requests

from datetime import date
 
from books_app import app, db, bcrypt
from books_app.models import Book, Author, User, Audience

"""
Run these tests with the command:
python -m unittest books_app.main.tests
"""

SERVER = '127.0.0.1:5000'

#################################################
# Setup
#################################################

def create_books():
    a1 = Author(name='Harper Lee')
    b1 = Book(
        title='To Kill a Mockingbird',
        publish_date=date(1960, 7, 11),
        author=a1
    )
    db.session.add(b1)

    a2 = Author(name='Sylvia Plath')
    b2 = Book(title='The Bell Jar', author=a2)
    db.session.add(b2)
    db.session.commit()

def create_user():
    password_hash = bcrypt.generate_password_hash('password').decode('utf-8')
    user = User(username='me1', password=password_hash)
    db.session.add(user)
    db.session.commit()

#################################################
# Tests
#################################################

class AuthTests(TestCase):
    """Tests for authentication (login & signup)."""
 
    def setUp(self):
        """Executed prior to each test."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        db.drop_all()
        db.create_all()

    def test_signup(self):
        # - Make a POST request to /signup, sending a username & password
        # - Check that the user now exists in the database
        credentials = {
            'username':'testuser',
            'password':'1234'
        }
        resp = self.app.post('/signup',
            follow_redirects=True,
            data=credentials
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(db.session.query(User).filter_by(username=credentials['username']).first())

    def test_signup_existing_user(self):
        # - Create a user
        # - Make a POST request to /signup, sending the same username & password
        # - Check that the form is displayed again with an error message
        credentials = {
            'username':'testuser',
            'password':'1234'
        }
        resp = self.app.post('/signup',
            follow_redirects=True,
            data=credentials
        )
        resp = self.app.post('/signup',
            follow_redirects=True,
            data=credentials
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue("That username is taken. Please choose a different one." in str(resp.data))


    def test_login_correct_password(self):
        # - Create a user
        # - Make a POST request to /login, sending the created username & password
        # - Check that the "login" button is not displayed on the homepage
        credentials = {
            'username':'testuser',
            'password':'1234'
        }
        resp = self.app.post('/signup',
            follow_redirects=True,
            data=credentials
        )
        resp = self.app.post('/login',
            follow_redirects=True,
            data=credentials
        )
        self.assertEqual(resp.status_code, 200)
        self.assertFalse('/login' in str(resp.data))

    def test_login_nonexistent_user(self):
        # - Make a POST request to /login, sending a username & password
        # - Check that the login form is displayed again, with an appropriate
        #   error message
        credentials = {
            'username':'testuser',
            'password':'1234'
        }
        resp = self.app.post('/login',
            follow_redirects=True,
            data=credentials
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue('No user with that username. Please try again.' in str(resp.data))


    def test_login_incorrect_password(self):
        # - Create a user
        # - Make a POST request to /login, sending the created username &
        #   an incorrect password
        # - Check that the login form is displayed again, with an appropriate
        #   error message
        credentials = {
            'username':'testuser',
            'password':'1234'
        }
        resp = self.app.post('/signup',
            follow_redirects=True,
            data=credentials
        )
        credentials['password'] = 'jkfasjdflkj'
        print(credentials)
        resp = self.app.post('/login',
            follow_redirects=True,
            data=credentials
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue("Password doesn&#39;t match. Please try again." in str(resp.data))


    def test_logout(self):
        # - Create a user
        # - Log the user in (make a POST request to /login)
        # - Make a GET request to /logout
        # - Check that the "login" button appears on the homepage
        
        credentials = {
            'username':'testuser',
            'password':'1234'
        }
        resp = self.app.post('/signup',
            follow_redirects=True,
            data=credentials
        )
        resp = self.app.post('/login',
            follow_redirects=True,
            data=credentials
        )
        resp = self.app.get('/logout',
            follow_redirects=True
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue('/login' in str(resp.data))

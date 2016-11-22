# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

# Templating
import jinja2

# For Google App Engine
import webapp2

# Access to app engine datastores
from google.appengine.ext import db

# Regex for pattern matching
import re

# Various modules for hashing, salts, and general security/authentication
import hashlib

import hmac

import random

import string

# Contains our secret
from secret import secret

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

# Utility functions for security
## Uses our secret constant to hash a string and avoid rainbow tables
def hash_str(s):
    return hmac.new(secret(), s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    s = h.split('|')[0]
    if h == make_secure_val(s):
        return s

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(9))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# User datastore

class User(db.Model):
    username = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    # Allows a user to be grabbed by their id
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)

    # Allows a user to be grabbed by their username
    @classmethod
    def by_username(cls, username):
        user = cls.all().filter('username =', username).get()
        return user

    # Registers a user by hashing their password and returning a new User instance
    @classmethod
    def register(cls, username, pw, email = None):
        pw_hash = make_pw_hash(username, pw)
        return cls(username = username, pw_hash = pw_hash, email = email)

    # Logs a user in by checking password validity and returning the user object,
    # if valid
    @classmethod
    def login(cls, name, pw):
        user = cls.by_username(name)
        if user and valid_pw(name, pw, user.pw_hash):
            return user

# Post entity
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateProperty(auto_now_add = True)
    created_by = db.StringProperty(required = True)

# Our superclass handler for all other blog related routes/classes/pages
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Sets a hashed cookie
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # Reads hashed cookies
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Logs the user in by setting a cookie
    def login(self, user):
        self.set_secure_cookie('user-id', str(user.key().id()))

    # Logs the user out by changing the user-id cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user-id=; Path=/')

    # Runs with every request from this Handler
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        # Grabs the info from the user-id cookie
        uid = self.read_secure_cookie('user-id')
        # Sets self.user so we have access to the currently logged in user
        self.user = uid and User.by_id(int(uid))

# Root of the blog
class MainPage(BlogHandler):
    def get(self):
        self.render_blog()

    def render_blog(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        self.render("blog.html", posts = posts)

# Sign up page for new users
class SignUp(BlogHandler):
    def get(self):
        self.render("signup.html")
    def post(self):
        have_error = False
        # Grab POST data from the form
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")

        # Make a dictionary from the username and email
        self.params = dict(username=self.username, email=self.email)

        # Validate the username against our validation function
        if not self.valid_username(self.username):
            # Add error_username if key to our dict if we get an error
            self.params['error_username'] = "Invalid Username"
            have_error = True

        # Same as above, but for password and checks verify field as well
        if not self.valid_password(self.password):
            self.params['error_password'] = "Invalid password"
            have_error = True
        elif self.password != self.verify:
            self.params['error_verify'] = "Passwords didn't match"
            have_error = True

        # Same as above, but for email
        if not self.valid_email(self.email):
            self.params['error_email'] = "Not a valid email"
            have_error = True

        # If there is an error, rerender the page, passing in our dict to preserve
        # user input
        if have_error:
            self.render("signup.html", **self.params)
        else:
            # Call the done function if successful
            self.done()

    def valid_username(self, username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USER_RE.match(username)
    
    def valid_password(self, password):
        USER_RE = re.compile(r"^.{3,20}$")
        return USER_RE.match(password)
    
    def valid_email(self, email):
        USER_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return USER_RE.match(email)

    def done(self):
        # Check if a user by the same username already exists in db
        user = User.by_username(self.username)

        # If so,
        if user:
            # rerender form with error message
            self.params['error_already'] = "That user already exists; please choose a different username"
            self.render("signup.html", **self.params)
        # If that user doesn't already exist,
        else:
            # call our register function,
            user = User.register(self.username, self.password, self.email)
            # put the new user into the datastore
            user.put()

            # log the user in
            self.login(user)
            # redirect to the thanks page
            self.redirect('/thanks')

# Page to thank new signups
class Thanks(BlogHandler):
    def get(self):
        if self.user:
            self.render('thanks.html', username = self.user.username)
        else:
            self.redirect('/signup')

class Login(BlogHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        self.params = dict(username = username) 

        user = User.login(username, password)
        if user:
            self.login(user)
            self.redirect('/thanks')
        else:
            self.params['error'] = 'Invalid login credentials'
            self.render('login.html', **self.params)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/login')

# Handler for new posts
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render_new_post()
        else:
            self.redirect('/login')
        
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        
        error = "Please make sure both a title/subject and some content are entered for your blog post."

        if subject and content:
            post = Post(subject=subject, content=content, created_by = self.user.username)
            post.put()
            post_id = post.key().id()
            self.redirect("/post-%s" % post_id)
        else:
            self.render_new_post(subject, content, error)

    def render_new_post(self, subject="", content="", error=""):
        self.render("blognewpost.html", subject=subject, content=content, error=error)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        
        if not post:
            self.error(404)
            return
        
        self.render("post.html", post = post)

class EditPostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        
        if not post:
            self.error(404)
            return
        elif not self.user:
            self.redirect('/login')
        
        if post.created_by == self.user.username:
            self.render("editpost.html", post = post)
        else:
            self.redirect('/')

    def post(self, post_id):
        subject = self.request.get("subject")
        content = self.request.get("content")

        self.params = dict(subject = subject, content = content)
        
        if subject and content:
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            post.subject = subject
            post.content = content
            post.put()
            self.redirect("/post-%s" % post_id)
        else:
            self.params['error'] = "Please make sure both a title/subject and some content are entered for your blog post."
            self.render("editpost.html", **self.params)

class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if self.user:
            self.redirect('/')
            if post.created_by == self.user.username:
                post.delete()
                # TODO: Figure out a more elegant solution here
                self.write('post deleted')
            else:
                self.write("you can't delete posts you didn't ... well post bro")
        else:
            self.redirect('/login')
    
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', SignUp),
                               ('/thanks', Thanks),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/newpost', NewPost),
                               ('/post-([0-9]+)', PostPage),
                               ('/edit-post-([0-9]+)', EditPostPage),
                               ('/delete-post-([0-9]+)', DeletePost)
                              ],
                              debug=True)
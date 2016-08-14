import os
import re
import random
import hashlib
import hmac
import webapp2
import jinja2
from string import letters
from google.appengine.ext import db

# template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'),
                               autoescape=True)


SECRET = '2144389555834132121234355589814413'

#######################################################
# Account and security users
#######################################################
# sha256


# Make a string of 5 letters, the salt
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


# Make a password hash
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


# Make sure that the hash from the database matches
# the new hash created based on what the user entered in
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


#######################################################
# hmac
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

#######################################################
# md5
# def hash_str(s):
# return hashlib.md5(s).hexdigest()


# Take a val and return that value, a pipe and the hmac of the val
def make_secure_val(val):
    return '%s|%s' % (val, hash_str(val))


# Take a secure val and check if it is valid
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def users_key(group='default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    ''' Stores user data in the DataStore'''
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        ''' Creates a new user entity '''
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Post(db.Model):
    ''' Stores post data in the DataStore '''
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty(default=0)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @classmethod
    def post_by_id(cls, uid):
        return Post.get_by_id(uid, parent=blog_key())


class Comments(db.Model):
    ''' Stores comments in the DataStore '''
    username = db.StringProperty()
    idpost = db.IntegerProperty()
    idcomment = db.StringProperty()
    textcomment = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_idcomment(cls, idcomment):
        c = db.GqlQuery('SELECT * FROM Comments WHERE idcomment = :1',
                        idcomment)
        return c

class Votes(db.Model):
    ''' Stores likes in the DataStore '''
    username = db.StringProperty()
    postid = db.StringProperty()
    votesid = db.StringProperty()
    likes = db.IntegerProperty(default=0)

    @classmethod
    def by_votesid(cls, votesid):
        v = db.GqlQuery('SELECT * FROM Votes WHERE votesid = :1', votesid)
        return v
import os
import re
import random
import hashlib
import hmac
import webapp2
import jinja2
from string import letters
from google.appengine.ext import db

#template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader('templates'),
                               autoescape = True)

SECRET = '2144389555834132121234355589814413'

#######################################################
# Account and security users
#######################################################
#sha256

# Make a string of 5 letters, the salt
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

# OLD
# def make_pw_hash(name, pw):
#     salt = make_salt()
#     h = hashlib.sha256(name + pw + salt).hexdigest()
#     return '%s,%s' % (h, salt)

# Make a password hash
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# Make sure that the hash from the database matches
# the new hash created based on what the user entered in
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# An element in the database to store all of our element
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

#######################################################
#hmac
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

#######################################################
#md5
#def hash_str(s):
#  return hashlib.md5(s).hexdigest()

# Take a val and return that value, a pipe and the hmac of the val
def make_secure_val(val):
    return '%s|%s' % (val, hash_str(val))

# Take a secure val and check if it is valid
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#######################################################
# Class User
# The user object that will be stored in the database
# db.Model makes it a data store object
#######################################################

class User(db.Model):
    name = db.StringProperty(required = True)
    # We DON'T store password in the database,
    # we store hash of the password
    pw_hash = db.StringProperty(required = True)
    # The email is not required
    email = db.StringProperty()

    # The next methods can be called on the User object
    # cls is refferring to this class user and not
    # an actual instance of a user

    # Give it an ID and with get_by_id we load
    # the user on to the databse
    # get_by_id is built into the datastore
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    # Looks up a user by its name
    # A datastore procedural code for doing the database look up
    # filter('name =', name) is ugual to:
    # select * from user where name = name
    # With get return the first instance
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    # register creates a new user object
    # It creates a password hash for that name and password
    # and than it creates a user object
    # this method doesn't store it in the database
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    # login
    @classmethod
    def login(cls, name, pw):
        # with cls.by_name(name) it refers to itself
        # it is called by_name and not user_by_name because
        # this function can be overwrite
        u = cls.by_name(name)

        # if it exist and the pw is valid (match the password hash
        # from the object with that name in the databse)
        # the user is returned
        if u and valid_pw(name, pw, u.pw_hash):
            return u





#######################################################
# BlogHandler: parent class for all handlers
#######################################################

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Call make_secure_val on val and store that in a cookie
    # using the header 'Set-Cookie'
    # the cookie will expire when we will close the browser
    # because we didn't include the expire time
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # Using the name, we find the cookie in the request
    # and we return a boolean depends if the cookie exist
    # and passes the check_secure_val
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Sets a secure cookie, user ID and it equals the user's ID
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Sets the cookie user id to nothing and Path=/
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # Function called by the App Engine framework
    # Checks to see if the user is logged or not.
    # checks for the user cookie with user_id and
    # if exist store it in self.user
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        # Read a secure cookie called user_id
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.render("index.html")




#######################################################
# Blog
#######################################################

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    likes = db.IntegerProperty(default = 0)
    last_modified = db.DateTimeProperty(auto_now = True)
    author = db.StringProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    @classmethod
    def post_by_id(cls, uid):
        return Post.get_by_id(uid, parent = blog_key())

class Comments(db.Model):
    username = db.StringProperty()
    idpost = db.IntegerProperty()
    idcomment = db.StringProperty()
    textcomment = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_idcomment(cls, idcomment):
        c = db.GqlQuery('SELECT * FROM Comments WHERE idcomment = :1', idcomment)
        return c

class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        comments = db.GqlQuery('SELECT * FROM Comments ORDER BY created DESC')
        self.render('front.html', posts = posts, comments=comments)

    def post(self):

        if self.user:
            username = self.user.name

            idpost = self.request.get('idp')
            key = db.Key.from_path('Post', int(idpost), parent=blog_key())
            p = db.get(key)
            comment = self.request.get('comment')
            deletecomment = self.request.get('deletecomment')
            commautor = self.request.get('commautor')
            editcomm = self.request.get('editcomm')
            textcomm = self.request.get('textcomm')
            editdone = self.request.get('editdone')
            checkererror = True;

            if username == p.author:
                like = self.request.get('like')
                delete = self.request.get('delete')
                edit = self.request.get('edit')

                if delete == "delete":
                    db.delete(p)
                    self.redirect('/blog/?')

                if edit == "edit":
                    sub = p.subject
                    cont = p.content
                    pos = p
                    checkererror = False;
                    self.render("editpost.html", p=pos, subject=sub, content=cont)

                if editdone == "editdone":

                    s = self.request.get('subject')
                    c = self.request.get('content')

                    if c and s:
                        p.subject = self.request.get('subject')
                        p.content = self.request.get('content')
                        p.put()
                        self.redirect('/blog/?')
                    else:
                        error = "Subject and content, please"
                        posts = greetings = Post.all().order('-created')
                        comments = Comments.all()
                        self.render("editpost.html", p=p, subject=s, content=c, error=error)
                        checkererror = False;


                if like == "like":
                    error = "You are the author, you can't vote"
                    posts = greetings = Post.all().order('-created')
                    comments = Comments.all()
                    self.render('front.html', posts=posts, error=error, comments=comments)
                    checkererror = False;

            else:
                like = self.request.get('like')
                delete = self.request.get('delete')
                edit = self.request.get('edit')

                if like == "like":
                    votes = Votes.all()
                    if votes.get():
                        votes = Votes.by_votesid(username+idpost).get()

                        if votes:
                            if votes.likes==0:
                                p.likes += 1
                                p.put()
                                self.redirect('/blog/?')

                            else:
                                error = "You can't put more than 1 like"
                                posts = greetings = Post.all().order('-created')
                                comments = Comments.all()
                                self.render('front.html', posts=posts, error=error, comments=comments)
                                checkererror = False;

                        elif not votes:
                                vote = Votes(username=username, postid=idpost, votesid=username+idpost, likes=1)
                                vote.put()
                                p.likes += 1
                                p.put()
                                self.redirect('/blog/?')

                    elif not votes.get():
                        vote = Votes(username=username, postid=idpost, votesid=username+idpost, likes=1)
                        vote.put()
                        p.likes += 1
                        p.put()
                        self.redirect('/blog/?')

                if delete == "delete":
                    error = "You are not the author, you can't delete it"
                    posts = greetings = Post.all().order('-created')
                    comments = Comments.all()
                    self.render('front.html', posts=posts, error=error, comments=comments)
                    checkererror = False;

                if edit == "edit":
                    error = "You are not the author, you can't edit it"
                    posts = greetings = Post.all().order('-created')
                    comments = Comments.all()
                    self.render('front.html', posts=posts, error=error, comments=comments)
                    checkererror = False;

            if comment:
                if p.author == self.user.name:
                    error = "You are the author, you can't comment it"
                    posts = greetings = Post.all().order('-created')
                    comments = Comments.all()
                    self.render('front.html', posts=posts, error=error, comments=comments)
                    checkererror = False;

                else:
                    allcomments = Comments.all()
                    existcomment = Comments.by_idcomment(username+idpost).get()

                    if existcomment:
                        error = "You have already commented"
                        posts = greetings = Post.all().order('-created')
                        comments = Comments.all()
                        self.render('front.html', posts=posts, error=error, comments=comments)
                        checkererror = False;


                    else:
                        comments = Comments(username=username, idpost=int(idpost), idcomment=username+idpost, textcomment=comment)
                        comments.put()
                        self.redirect('/blog/?')

            if username == commautor:
                editcommentdone = self.request.get('editcommentdone')

                if deletecomment == "deletecomment":
                    comments = Comments.all()

                    if comments.get():
                        comment = Comments.by_idcomment(username+idpost).get()

                        if comment:
                            db.delete(comment)
                            self.redirect('/blog/?')

                        elif not comments:
                            self.redirect('/blog/?')

                    elif not comments.get():
                        self.redirect('/blog/?')

                if editcomm == "editcomm":
                    comments = Comments.all()

                    if comments.get():
                        comment = Comments.by_idcomment(username+idpost).get()

                        if comment:
                            textcommdamod = comment.textcomment
                            postcomm = p
                            self.render("editcomment.html", p=postcomm, comment=comment, textcomm=textcommdamod)

                        elif not comments:
                            self.redirect('/blog/?')

                    elif not comments.get():
                        self.redirect('/blog/?')

                if editcommentdone == "editcommentdone":
                    #self.write(textcomm)
                    comments = Comments.all()

                    if comments.get():
                        comment = Comments.by_idcomment(username+idpost).get()
                        if comment:
                            #self.write(textcomm)

                            if textcomm:
                                comment.textcomment = textcomm
                                comment.put()
                                self.redirect('/blog/?')
                            else:
                                error = "Subject and content, please"
                                self.render("editcomment.html", p=p,  comment=comment, content=textcomm, error=error)
                                checkererror = False;

                        elif not comments:
                            self.redirect('/blog/?')
                    elif not comments.get():
                        self.redirect('/blog/?')

            elif(username != commautor and checkererror):
                error = "You are not the author, you can't delete or edit it"
                posts = greetings = Post.all().order('-created')
                comments = Comments.all()
                self.render('front.html', posts=posts, error=error, comments=comments)

        else:
            error = "You are not logged"
            posts = greetings = Post.all().order('-created')
            comments = Comments.all()
            self.render('login-form.html', error=error)


class PostPage(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)

class Votes(db.Model):
    username = db.StringProperty()
    postid = db.StringProperty()
    votesid = db.StringProperty()
    likes = db.IntegerProperty(default = 0)

    @classmethod
    def by_votesid(cls, votesid):
        v = db.GqlQuery('SELECT * FROM Votes WHERE votesid = :1', votesid)
        return v

class EditPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("editpost.html")
        else:
            self.redirect("/login")

class EditComment(BlogHandler):
    def get(self):
        if self.user:
            self.render("editcomment.html")
        else:
            self.redirect("/login")

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect("/login")

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.request.get('author')

        if subject and content:
            p = Post(parent = blog_key(), subject=subject, content=content, author=author)
            p.put()
            post_id = str(p.key().id())
            post_key = str(p.key())
            self.redirect('/blog/?')
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Likes handler
class likes(object):
    def get(self):
        self.render("signup-form.html")
        self.arg = arg

# Signup handler
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False

        # Get all the values out of the request
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        # Check if the values are all valid
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        # If there is an error we re-render the form with
        # the error messages and the values
        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

# Register handler
# It inherits from the class Signup
class Register(Signup):
    def done(self):

        # Make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)

        # If the error doesn't exist
        else:
            # the user is registered
            u = User.register(self.username, self.password, self.email)

            # the user is stored in the database
            u.put()

            # The login function sets the cookies
            self.login(u)

            # Here we can redirect to the blog page or the welcome page
            # self.redirect('/blog')
            self.redirect('/unit3/welcome')

# - Unit3Welcome handler checks to see if self.user
# - self.user gets set up in the initialize function
#   where it reads the coockie and make sure if the cookie is
#   valid and sets the user on the !handler!!)
# - Unit3Welcome inherits from BlogHandler it has the
#   access to that user.
class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')

# Login handler
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        # The login function is called on the user objects
        # It returns the user if this is a valid username
        # and pwd combination
        u = User.login(username, password)
        if u:
            # The login function is called on the log handler
            self.login(u)

            # Here we can redirect to the blog page or the welcome page
            # self.redirect('/blog')
            self.redirect('/unit3/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)

class Logout(BlogHandler):
    def get(self):

        # logout() sets the cookie user id to nothing
        # (see in the BlogHandler)
        self.logout()

        # Here we can redirect to the blog page or the signup page
        self.redirect('/login')
        #self.redirect('/signup')


class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/unit2/signup')

#######################################################
# Rot13 Algorithm
#######################################################

class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text=rot13)

#######################################################
#######################################################

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/blog/editpost', EditPost)
                               ],
                              debug=True)

#######################################################
#######################################################

import os
import re
import random
import hashlib
import hmac
import webapp2
import jinja2
import models
from string import letters
from google.appengine.ext import db

#######################################################
# BlogHandler: parent class for all handlers
#######################################################


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
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # Using the name, we find the cookie in the request
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Sets a secure cookie, user ID and it equals the user's ID
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Sets the cookie user id to nothing and Path=/
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

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


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class BlogFrontLoggedOut(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        comments = db.GqlQuery('SELECT * FROM Comments ORDER BY created DESC')
        self.render('front.html', posts=posts, comments=comments)

    def post(self):
        error = "You are not logged"
        posts = greetings = Post.all().order('-created')
        comments = Comments.all()
        self.render('login-form.html', error=error)


class EditComment(BlogHandler):

    def get(self, idpost):
            if self.user:

                key = db.Key.from_path('Post', int(idpost), parent=blog_key())
                p = db.get(key)

                if not p:
                    self.error(404)
                    return

                comments = Comments.all()
                comment = Comments.by_idcomment(self.user.name+idpost).get()
                if comment:
                    username = self.user.name
                    commautor = comment.username
                    if username == commautor:
                        self.render('editcomment.html', p=p, comment=comment)
                    else:
                        error = "You are not the author"
                        comments = Comments.all()
                        self.render('editcomment.html',
                                    p=p,
                                    error=error,
                                    comment=comment)
                else:
                    error = "You are not the author"
                    comments = Comments.all()
                    self.render('editcomment.html',
                                p=p,
                                error=error,
                                comment=comment)
            else:
                self.redirect("/login")

    def post(self, par):
        if not self.user:
            return self.redirect('/login')

        username = self.user.name

        idpost = self.request.get('idp')
        key = db.Key.from_path('Post', int(idpost), parent=blog_key())
        p = db.get(key)
        commautor = self.request.get('commautor')
        editcomm = self.request.get('editcomm')
        comment = self.request.get('comment')
        textcomm = self.request.get('textcomm')

        if username == commautor:

            editcommentdone = self.request.get('editcommentdone')

            if editcommentdone == "editcommentdone":
                    comments = Comments.all()
                    if comments.get():
                        comment = Comments.by_idcomment(username+idpost).get()
                        if comment:

                            if textcomm:
                                comment.textcomment = textcomm
                                comment.put()
                                self.redirect('/blog/?')
                            else:
                                error = "Content please!"
                                self.render("editcomment.html",
                                            p=p,
                                            comment=comment,
                                            content=textcomm,
                                            error=error)

                        elif not comments:
                            self.redirect('/blog/?')
                    elif not comments.get():
                        self.redirect('/blog/?')

        else:
            error = "You are not the author, you can't edit other comments"
            posts = greetings = Post.all().order('-created')
            comments = Comments.all()
            self.render('front.html',
                        posts=posts,
                        error=error,
                        comments=comments)


class EditPost(BlogHandler):

    def get(self, idpost):
            if self.user:

                key = db.Key.from_path('Post', int(idpost), parent=blog_key())
                p = db.get(key)

                if not p:
                    self.error(404)
                    return

                username = self.user.name
                if username == p.author:
                    self.render('editpost.html', p=p)
                else:
                    error = "You are not the author"
                    self.render('editpost.html',
                                p=p,
                                error=error)
            else:
                self.redirect("/login")

    def post(self, par):
        if not self.user:
            return self.redirect('/login')

        username = self.user.name

        idpost = self.request.get('idp')
        key = db.Key.from_path('Post', int(idpost), parent=blog_key())
        p = db.get(key)
        editdone = self.request.get('editdone')

        if username == p.author:
            edit = self.request.get('edit')

            if edit == "edit":
                sub = p.subject
                cont = p.content
                pos = p
                self.render("editpost.html",
                            p=pos, subject=sub,
                            content=cont)

            if editdone == "editdone":

                subjectchanged = self.request.get('subject')
                contentchanged = self.request.get('content')

                if contentchanged and subjectchanged:
                    p.subject = self.request.get('subject')
                    p.content = self.request.get('content')
                    p.put()
                    self.redirect('/blog/?')
                else:
                    error = "Subject and content, please"
                    posts = greetings = Post.all().order('-created')
                    comments = Comments.all()
                    self.render("editpost.html",
                                p=p,
                                subject=subjectchanged,
                                content=contentchanged,
                                error=error)

        else:
            error = "You are not the author, you can't delete or edit it"
            posts = greetings = Post.all().order('-created')
            comments = Comments.all()
            self.render('front.html',
                        posts=posts,
                        error=error,
                        comments=comments)


class DelComment(BlogHandler):

    def get(self, idpost):
        if self.user:

            key = db.Key.from_path('Post', int(idpost), parent=blog_key())
            p = db.get(key)

            if not p:
                self.error(404)
                return

            username = self.user.name
            comments = Comments.all()
            comment = Comments.by_idcomment(username+idpost).get()

            if comment:
                commautor = comment.username
                if username == commautor:
                    self.render('deletecomment.html', p=p)

                else:
                    error = "You are not the author"
                    self.render('deletecomment.html',
                                p=p,
                                error=error)
            else:
                error = "You are not the author, you can't edit other posts"
                self.render('deletecomment.html',
                            p=p,
                            error=error)
        else:
            self.redirect("/login")

    def post(self, par):
        if not self.user:
            return self.redirect('/login')

        username = self.user.name

        idpost = self.request.get('idp')
        key = db.Key.from_path('Post', int(idpost), parent=blog_key())
        p = db.get(key)

        comments = Comments.all()
        comment = Comments.by_idcomment(username+idpost).get()

        if comment:
            commautor = comment.username

            deletecommentyes = self.request.get('deletecommentyes')
            if username == commautor:

                if deletecommentyes == "deletecommentyes":
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

        else:
            error = "You are not the author, you can't delete it"
            posts = greetings = Post.all().order('-created')
            comments = Comments.all()
            return self.render('front.html',
                               posts=posts,
                               error=error,
                               comments=comments)


class DelPost(BlogHandler):

    def get(self, idpost):
        if self.user:

            key = db.Key.from_path('Post', int(idpost), parent=blog_key())
            p = db.get(key)

            if not p:
                self.error(404)
                return

            username = self.user.name
            if username == p.author:
                self.render('deletepost.html', p=p)
            else:
                error = "You are not the author, you can't delete other posts"
                self.render('deletepost.html',
                            p=p,
                            error=error)
        else:
            self.redirect("/login")

    def post(self, par):
        if not self.user:
            return self.redirect('/login')

        username = self.user.name
        idpost = self.request.get('idp')
        key = db.Key.from_path('Post', int(idpost), parent=blog_key())
        p = db.get(key)

        deleteyes = self.request.get('deleteyes')
        if deleteyes == "deleteyes":
            if username == p.author:
                    db.delete(p)
                    self.redirect('/blog/')

            else:
                error = "You are not the author, you can't delete it"
                posts = greetings = Post.all().order('-created')
                comments = Comments.all()
                self.render('front.html',
                            posts=posts,
                            error=error,
                            comments=comments)


class LikePost(BlogHandler):

    def get(self, idpost):
        if self.user:

            key = db.Key.from_path('Post', int(idpost), parent=blog_key())
            p = db.get(key)

            if not p:
                self.error(404)
                return

            username = self.user.name
            if not username == p.author:
                self.render('like.html', p=p)
            else:
                error = "You are not the author, you can't delete other posts"
                self.render('like.html',
                            p=p,
                            error=error)

        else:
            self.redirect("/login")

    def post(self, par):
        if not self.user:
            return self.redirect('/login')

        username = self.user.name

        idpost = self.request.get('idp')
        key = db.Key.from_path('Post', int(idpost), parent=blog_key())
        p = db.get(key)

        likeyes = self.request.get('likeyes')

        if likeyes == "likeyes":
            if username == p.author:
                    error = "You are the author, you can't vote, "
                    posts = greetings = Post.all().order('-created')
                    comments = Comments.all()
                    self.render('front.html',
                                posts=posts,
                                error=error,
                                comments=comments)
            else:
                votes = Votes.all()
                if votes.get():
                    votes = Votes.by_votesid(username+idpost).get()

                    if votes:
                        if votes.likes == 0:
                            p.likes += 1
                            p.put()
                            self.redirect('/blog/?')

                        else:
                            error = "You can't put more than 1 like, "
                            "Back to blog page!"
                            posts = Post.all().order('-created')
                            comments = Comments.all()
                            self.render('like.html', error=error, p=p)

                    elif not votes:
                            vote = Votes(username=username,
                                         postid=idpost,
                                         votesid=username+idpost,
                                         likes=1)
                            vote.put()
                            p.likes += 1
                            p.put()
                            self.redirect('/blog/?')

                elif not votes.get():
                    vote = Votes(username=username,
                                 postid=idpost,
                                 votesid=username+idpost,
                                 likes=1)
                    vote.put()
                    p.likes += 1
                    p.put()
                    self.redirect('/blog/?')


class CommPost(BlogHandler):

    def get(self, idpost):

        if self.user:

            key = db.Key.from_path('Post', int(idpost), parent=blog_key())
            p = db.get(key)

            if not p:
                self.error(404)
                return

            username = self.user.name
            if not username == p.author:
                self.render("newcomment.html", p=p)
            else:
                error = "You are the author, you can't comment it"
                self.render('newcomment.html',
                            p=p,
                            error=error)

        else:
            self.redirect("/login")

    def post(self, par):
        if not self.user:
            return self.redirect('/login')

        username = self.user.name

        idpost = self.request.get('idp')
        key = db.Key.from_path('Post', int(idpost), parent=blog_key())
        p = db.get(key)
        newcommentdone = self.request.get('newcommentdone')

        if newcommentdone == "newcommentdone":

                if p.author == self.user.name:
                    error = "You are the author, you can't comment it"
                    posts = greetings = Post.all().order('-created')
                    comments = Comments.all()
                    self.render('front.html',
                                posts=posts,
                                error=error,
                                comments=comments)

                else:
                    allcomments = Comments.all()
                    existcomment = Comments.by_idcomment(username+idpost).get()

                    if existcomment:
                        error = "You have already commented, "
                        "Back to blog page!"
                        posts = greetings = Post.all().order('-created')
                        comments = Comments.all()
                        self.render('newcomment.html',
                                    error=error, p=p)
                    else:
                        textcomm = self.request.get("textcomm")

                        if textcomm:
                            comments = Comments(username=username,
                                                idpost=int(idpost),
                                                idcomment=username+idpost,
                                                textcomment=textcomm)
                            comments.put()
                            self.redirect('/blog/')
                        else:
                            error = "No content!"
                            self.render('newcomment.html',
                                        error=error, p=p)


class BlogFront(BlogHandler):

    def get(self):
        posts = greetings = Post.all().order('-created')
        comments = db.GqlQuery('SELECT * FROM Comments ORDER BY created DESC')
        self.render('front.html', posts=posts, comments=comments)

    def post(self):
        if self.user:

            idpost = self.request.get('idp')
            key = db.Key.from_path('Post', int(idpost), parent=blog_key())
            p = db.get(key)
            postAuthor = p.author
            commautor = self.request.get('commautor')

            # Del post
            delete = self.request.get('delete')
            if delete == "delete":
                self.redirect('/blog/delpost/%s' % str(p.key().id()))

            # Del comment
            deletecomment = self.request.get('deletecomment')
            if deletecomment == "deletecomment":
                self.redirect('/blog/delcomment/%s' % str(p.key().id()))

            # New comment
            addcomment = self.request.get('addcomment')
            if addcomment == "addcomment":
                self.redirect('/blog/commpost/%s' % str(p.key().id()))

            # New like
            like = self.request.get('like')
            if like == "like":
                self.redirect('/blog/addlike/%s' % str(p.key().id()))

            # Edit Post
            edit = self.request.get('edit')
            if edit == "edit":
                self.redirect('/blog/editPost/%s' % str(p.key().id()))

            # Edit comm
            editcomm = self.request.get('editcomm')
            if editcomm == "editcomm":
                self.redirect('/blog/editComment/%s' % str(p.key().id()))

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


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.request.get('author')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, author=author)
            p.put()
            post_id = str(p.key().id())
            post_key = str(p.key())
            self.redirect('/blog/?')
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


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

        params = dict(username=self.username,
                      email=self.email)

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


class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/unit2/signup')


#######################################################
#######################################################

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/editComment/([0-9]+)', EditComment),
                               ('/blog/editPost/([0-9]+)', EditPost),
                               ('/blog/delcomment/([0-9]+)', DelComment),
                               ('/blog/delpost/([0-9]+)', DelPost),
                               ('/blog/addlike/([0-9]+)', LikePost),
                               ('/blog/commpost/([0-9]+)', CommPost),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blogout/?', BlogFrontLoggedOut),
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

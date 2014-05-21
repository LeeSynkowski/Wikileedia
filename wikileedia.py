import webapp2
import cgi
import os
import urllib
import jinja2
import re
import random
import hashlib
import string
import json
import time
from google.appengine.ext import db
from google.appengine.api import memcache
#Environment variables
JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)
DEBUG = True
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

#Database
class Page(db.Model):
    content = db.TextProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)

class User(db.Model):
    username = db.StringProperty(required = True)
    password_hash = db.StringProperty(required = True)
    email = db.StringProperty(required = False)


class MainPage(webapp2.RequestHandler):
    def get(self):
        page_content = {}
        #get welcome page from db add its content to the page var
        welcome = Page.get_by_key_name('welcome')
        if welcome == None:
            welcome= Page(key_name='welcome',content = "Welcome to Wikileedia!")
            welcome.put()    
        ####################    
        ### Adding a test page to the database
        test = Page.get_by_key_name('test')
        if test == None:
            test = Page(key_name='test',content = "This is the test page")
            test.put()
          
        page_content['content'] = welcome.content
        if user_logged_in(self):
            page_content['page'] = "/_edit/welcome"
            self.response.out.write(print_form('loggedinpage.html',page_content))
        else:
            self.response.out.write(print_form('loggedoutpage.html',page_content))

class Signup(webapp2.RequestHandler):
    def get(self):
        signupform_template_values = {'t_username':"",'t_password':"",'t_verify':"",'t_email':"",'t_username_message':"",'t_password_message':"",'t_verify_message':"",'t_email_message':""}
        self.response.out.write(print_form('signupform.html',signupform_template_values))

    def post(self):
        signupform_template_values = {'t_username':"",'t_password':"",'t_verify':"",'t_email':"",'t_username_message':"",'t_password_message':"",'t_verify_message':"",'t_email_message':"",'t_user_message':""}
        
        #ideal case
        if all_fields_correct(self) and user_not_in_database(self):
            username = str(self.request.get("username"))
            password = str(self.request.get("password"))
            user_hash = str(make_pw_hash(username,password,make_salt()))
            if self.request.get("email") != "":
                email = str(self.request.get("email"))
                new_user = User(key_name=username,username = username,password_hash = user_hash,email = email)
            else:
                new_user = User(key_name=username, username = username,password_hash = user_hash)
            new_user.put()
            self.response.headers.add_header('Set-Cookie', "name=%s; Path=/"%username)
            self.response.headers.add_header('Set-Cookie', "password=%s; Path=/"%user_hash)
            self.redirect('/')
            
        #user name check
        signupform_template_values['t_username'] = self.request.get("username")
        if (not valid_username(self.request.get("username"))) or (self.request.get("username") == ""):
            signupform_template_values['t_username_message'] = "Thats not a valid username"
            
        #password check
        signupform_template_values['t_password'] = self.request.get("password")
        signupform_template_values['t_verify'] = self.request.get("verify")
        if (not valid_password(self.request.get("password"))) or (self.request.get("password") == ""):
            signupform_template_values['t_password_message'] = "That's not a valid password"
            signupform_template_values['t_password'] = ""
            signupform_template_values['t_verify'] = ""
        if self.request.get("password") != self.request.get("verify"):
            signupform_template_values['t_verify_message'] = "Passwords don't match"
        else:
            if self.request.get("password") != self.request.get("verify"):
                signupform_template_values['t_verify_message'] = "Passwords don't match"
                signupform_template_values['t_password'] = ""
                signupform_template_values['t_verify'] = ""
                
        #email check
        if (not valid_email(self.request.get("email"))):
            signupform_template_values['t_email_message'] = "Invalid email address"
        if self.request.get("email")=="":
            signupform_template_values['t_email_message'] = ""
            
        #user in database check
        if (not user_not_in_database(self)):
            signupform_template_values['t_username_message'] = "User already in database"
            signupform_template_values['t_username'] = ""
        self.response.out.write(print_form('signupform.html',signupform_template_values))

class Login(webapp2.RequestHandler):
    def get(self):
        template_values = {'t_username':"",'t_password':"",'t_user_message':""}
        self.response.out.write(print_form('login.html',template_values))

    def post(self):
        username = str(self.request.get("username"))
        password = str(self.request.get("password"))
        this_user = User.get_by_key_name(username)
        if not user_not_in_database(self):
            h = str(this_user.password_hash)
        else:
            h = 5
        if not user_not_in_database(self) and valid_pw(username,password,h):
            h = str(this_user.password_hash)
            self.response.headers.add_header('Set-Cookie', "name=%s; Path=/"%username)
            self.response.headers.add_header('Set-Cookie', "password=%s; Path=/"%h)
            self.redirect('/')
        else:
            self.response.headers.add_header('Set-Cookie', "name=; Path=/")
            self.response.headers.add_header('Set-Cookie', "password=; Path=/")
            template_values = {'t_username':"",'t_password':"",'t_user_message':"Invalid Login"}
            self.response.out.write(print_form('login.html',template_values))

class Logout(webapp2.RequestHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', "name=; Path=/")
        self.response.headers.add_header('Set-Cookie', "password=; Path=/")
        self.redirect('/')
        
class EditPage(webapp2.RequestHandler):
    def get(self,page_key):
        entry_key = page_key.strip("/")
        if not user_logged_in(self):        
            self.redirect('/'+ entry_key)
        template_values = {'content':"",'page':"/" + entry_key}
        page = Page.get_by_key_name(entry_key)
        if page != None:
            template_values['content'] = page.content
        self.response.out.write(print_form('loggedinpageediting.html',template_values))
        
    def post(self,page_key):
        #add the form value to the
        #self.response.out.write("responding to single arg post")
        entry_key = page_key.strip("/")
        #im not actually changing the value in the db
        page = Page.get_by_key_name(entry_key)
        if page == None:
            page = Page(key_name=entry_key)
        page.content = self.request.get("content")
        page.put()
        self.redirect('/'+ entry_key)
    
    
class WikiPage(webapp2.RequestHandler):
    def get(self,page_key):
        template_values = {'content':"",'page':"/_edit" + page_key}
        #see if page is in the db
        #if user logged in display loggedinpage
        page = Page.get_by_key_name(page_key.strip("/"))
        if page == None:
            self.redirect('/_edit'+ page_key)
            #template_values['content'] = page.content
        else:
            template_values['content'] = page.content
        if user_logged_in(self):
            self.response.out.write(print_form('loggedinpage.html',template_values))
        else:
            self.response.out.write(print_form('loggedoutpage.html',template_values))
        
def print_form(form_name,template_values):
    template = JINJA_ENVIRONMENT.get_template(form_name)
    return template.render(template_values)

def all_fields_correct(obj):
    if (valid_username(obj.request.get("username")) and valid_password(obj.request.get("password")) and obj.request.get("password") == obj.request.get("verify")) and (valid_email(obj.request.get("email")) or obj.request.get("email")==""):
        return True
    else:
        return False
    
def user_not_in_database(obj):
    username = str(obj.request.get("username"))
    this_user = User.get_by_key_name(username)
    #same_names = db.GqlQuery("SELECT * FROM User WHERE username='%s'"%username)
    if this_user is None:
        return True
    return False


def user_logged_in(obj):
    #if user cookies are present, we return true
    if obj.request.cookies.get("name") != "":
        return True
    return False

def valid_username(username):
    return USERNAME_RE.match(username)

def valid_password(password):
    return PASSWORD_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw,salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name,pw,salt) 

application = webapp2.WSGIApplication([('/',MainPage),
                                       ('/signup', Signup),
                                       ('/login', Login),
                                       ('/logout', Logout),
                                       ('/_edit' + PAGE_RE, EditPage),
                                       (PAGE_RE, WikiPage)],
                                       debug=DEBUG)
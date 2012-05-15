import os
import sys
import jinja2
import webapp2
import config
from webapp2_extras import auth
from webapp2_extras import sessions
from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

def user_required(handler):
    def check_login(self, *args, **kwargs):
        auth = self.auth
        if not auth.get_user_by_session():
            self.redirect(self.auth_config['login_url'])
        else:
            return handler(self, *args, **kwargs)

    return check_login

class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def dispatch(self):
        try:
            response = super(BaseHandler, self).dispatch()
            self.response.write(response)
        finally:
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def auth(self):
        return auth.get_auth()

    @webapp2.cached_property
    def session_store(self):
        return sessions.get_store(request=self.request)

    @webapp2.cached_property
    def auth_config(self):
        return {
            'login_url' : self.uri_for('login'),
            'logout_url' : self.uri_for('logout')
        }

    def set_flash(self, msg):
        self.session_store.get_session()['_flash'] = msg

    def get_flash(self):
        flash_msg = self.session_store.get_session()['_flash']
        del self.session_store.get_session()['_flash']
        return flash_msg


class LoginHandler(BaseHandler):
    def get(self):
        try:
            self.response.out.write("<div class='success'>%s</div>" % self.get_flash())
        except:
            self.response.out.write("<p>Please login:</p>")

        return """
<!DOCTYPE hml>
<html>
    <head>
        <title>webapp2 auth</title>
    </head>
    <body>
    <form action="%s" method="post">
        <fieldset>
            <legend>Login form</legend>
            <label>Username <input type="text" name="username" placeholder="Your username" /></label>
            <label>Password <input type="password" name="password" placeholder="Your password" /></label>
            <label>Remember me? <input type="checkbox" name="remember_me" placeholder="Remember me?" /></label>
        </fieldset>
        <button>Login</button>
    </form>
</html>
        """ % self.request.url

    def post(self):
        username = self.request.POST.get("username")
        password = self.request.POST.get("password")
        remember_me = True if self.request.POST.get('remember_me') == 'on' else False

        try:
            self.auth.get_user_by_password(username, password, remember = remember_me)
            self.set_flash("You've logged in!")
            self.redirect(self.uri_for("secure"))
        except (InvalidAuthIdError, InvalidPasswordError), e:
            return "Login error. Try again: <a href='%s'>Login</a>" % (self.auth_config['login_url'])

class CreateUserHandler(BaseHandler):
    def get(self):
        return """
<!DOCTYPE hml>
<html>
    <head>
        <title>webapp2 auth</title>
    </head>
    <body>
    <form action="%s" method="post">
        <fieldset>
            <legend>Create user form</legend>
            <label>Username <input type="text" name="username" placeholder="Your username" /></label>
            <label>Email <input type="text" name="email" placeholder="Your email" /></label>
            <label>Password <input type="password" name="password" placeholder="Your password" /></label>
        </fieldset>
        <button>Create user</button>
    </form>
</html>
        """ % self.request.url 

    def post(self):
        username = self.request.POST.get('username')
        password = self.request.POST.get('password')
        email = self.request.POST.get('email')

        user = self.auth.store.user_model.create_user(username, password_raw = password, email = email)
        if not user[0]: #returns a tuple with [boolean, user_info]
            return 'Create user error: %s' % str(user)
        else:
            self.set_flash("Thank you for registering. Please login!")
            self.redirect(self.auth_config['login_url'])


class LogoutHandler(BaseHandler):
    """ Destroy user session and redirect """
    def get(self):
        self.auth.unset_session()
        # User is logged out, let's try redirecting to login page
        try:
            self.redirect(self.auth_config['login_url'])
        except (AttributeError, KeyError), e:
            return "User is logged out"

class SecureRequestHandler(BaseHandler):
    @user_required
    def get(self, **kwargs):
        self.response.out.write("<div class='success'>%s</div>" % self.get_flash())
        user_session = self.auth.get_user_by_session()
        user = self.auth.store.user_model.get_by_auth_token(user_session['user_id'], user_session['token'])
        try:
            return "Secure zone %s <a href='%s'>Logout</a>" % (user, self.auth_config['logout_url'])
        except (AttributeError, KeyError), e:
            return "Secure zone"

class DisplayPropHandler(BaseHandler):
    @user_required
    def get(self, **kwargs):
        user_session = self.auth.get_user_by_session()
        user = self.auth.store.user_model.get_by_auth_token(user_session['user_id'], user_session['token'])
        if user:
            return "your email: %s" % user[0].email
        else:
            return "Not found"

app = webapp2.WSGIApplication([webapp2.Route('/login/', LoginHandler, name='login'),
                               webapp2.Route('/logout/', LogoutHandler, name='logout'), 
                               webapp2.Route('/secure', SecureRequestHandler, name='secure'),
                               webapp2.Route('/display', DisplayPropHandler, name='display'),
                               webapp2.Route('/', CreateUserHandler, name='create-user')], 
                               debug=True, config=config.webapp2_config)

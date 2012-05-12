import webapp2
import config
from webapp2_extras import auth
from webapp2_extras.routes import RedirectRoute
from webapp2_extras import sessions
from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

from webapp2_extras.appengine.auth.models import User
from google.appengine.ext.ndb import model

# class CustomUser(User):
#     email = model.StringProperty(required=True)

def user_required(handler):
    """
    Simple decorator to check if a user's associated with the current
    session. Will fail if there's no session present
    """
    def check_login(self, *args, **kwargs):
        auth = self.auth
        if not auth.get_user_by_session():
            # If handler has no login_url specified invoke a 403 error
            try:
                self.redirect(self.auth_config['login_url'], abort=True)
            except (AttributeError, KeyError), e:
                self.abort(403)
        else:
            return handler(self, *args, **kwargs)

    return check_login

# auth.default_config = {
#     # "user_model" : CustomUser,
#     'cookie_name' : 'testauth'
# }

class BaseHandler(webapp2.RequestHandler):

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


class LoginHandler(BaseHandler):
    def get(self):
        return """
			<!DOCTYPE hml>
			<html>
				<head>
					<title>webapp2 auth example</title>
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
            self.redirect('/secure')
        except (InvalidAuthIdError, InvalidPasswordError), e:
            return "Login error. Try again: <a href='%s'>Login</a>" % (self.auth_config['login_url'])

class CreateUserHandler(BaseHandler):
    def get(self):

        return """
			<!DOCTYPE hml>
			<html>
				<head>
					<title>webapp2 auth example</title>
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
            # User is created, redirect to login page
            try:
                self.redirect(self.auth_config['login_url'], abort=True)
            except (AttributeError, KeyError), e:
                self.abort(403)


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
        user_session = self.auth.get_user_by_session()
        user = self.auth.store.user_model.get_by_auth_token(user_session['user_id'], user_session['token'])
        user[0].username = 'a'
        user[0].put()

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

app = webapp2.WSGIApplication([RedirectRoute('/login/', LoginHandler, name='login'),
                               RedirectRoute('/logout/', LogoutHandler, name='logout'), 
                               RedirectRoute('/secure', SecureRequestHandler, name='secure'),
                               RedirectRoute('/display', DisplayPropHandler, name='display'),
                               RedirectRoute('/', CreateUserHandler, name='create-user')], 
                               debug=True, config=config.webapp2_config)

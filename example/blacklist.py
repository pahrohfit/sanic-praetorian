from tortoise.contrib.sanic import register_tortoise
from tortoise.models import Model
from tortoise import fields
from tortoise.exceptions import DoesNotExist

from sanic import Sanic, json

import sanic_praetorian
from sanic_praetorian import Praetorian
from sanic_mailing import Mail


_guard = Praetorian()
_mail = Mail()


# A generic user model that might be used by an app powered by sanic-praetorian
class User(Model):
    """
    Provides a basic user model for use in the tests
    """

    class Meta:
        table = "User"

    id = fields.IntField(pk=True)
    username = fields.CharField(unique=True, max_length=255)
    password = fields.CharField(max_length=255)
    email = fields.CharField(max_length=255, unique=True)
    roles = fields.CharField(max_length=255, default='')
    is_active = fields.BooleanField(default=True)

    def __str__(self):
        return f"User {self.id}: {self.username}"

    @property
    def rolenames(self):
        """
        *Required Attribute or Property*

        sanic-praetorian requires that the user class has a :py:meth:``rolenames``
        instance attribute or property that provides a list of strings that
        describe the roles attached to the user instance.

        This can be a seperate table (probably sane), so long as this attribute
        or property properly returns the associated values for the user as a
        list of strings.
        """
        try:
            return self.roles.split(",")
        except Exception:
            return []

    @classmethod
    async def lookup(cls, username=None, email=None):
        """
        *Required Method*

        sanic-praetorian requires that the user class implements a :py:meth:``lookup()``
        class method that takes a single ``username`` or ``email`` argument and
        returns a user instance if there is one that matches or ``None`` if
        there is not.
        """
        try:
            if username:
                return await cls.filter(username=username).get()
            elif email:
                return await cls.filter(email=email).get()
            else:
                return None
        except DoesNotExist:
            return None

    @classmethod
    async def identify(cls, id):
        """
        *Required Attribute or Property*

        sanic-praetorian requires that the user class implements an :py:meth:``identify()``
        class method that takes a single ``id`` argument and returns user instance if
        there is one that matches or ``None`` if there is not.
        """
        try:
            return await cls.filter(id=id).get()
        except DoesNotExist:
            return None

    @property
    def identity(self):
        """
        *Required Attribute or Property*

        sanic-praetorian requires that the user class has an :py:meth:``identity``
        instance attribute or property that provides the unique id of the user
        instance
        """
        return self.id


def create_app(db_path=None):
    """
    Initializes the sanic app for the test suite. Also prepares a set of routes
    to use in testing with varying levels of protections
    """
    sanic_app = Sanic('sanic-testing')
    # In order to process more requests after initializing the app,
    # we have to set degug to false so that it will not check to see if there
    # has already been a request before a setup function
    sanic_app.config.FALLBACK_ERROR_FORMAT = "json"

    # sanic-praetorian config
    sanic_app.config.SECRET_KEY = "top secret"
    sanic_app.config["JWT_ACCESS_LIFESPAN"] = {"hours": 1000}
    sanic_app.config["JWT_REFRESH_LIFESPAN"] = {"days": 1000}

    # sanic-mailing config
    sanic_app.config.MAIL_SERVER = 'localhost:25'
    sanic_app.config.MAIL_USERNAME = ''
    sanic_app.config.MAIL_PASSWORD = ''
    sanic_app.config.MAIL_FROM = 'fake@fake.com'
    sanic_app.config.JWT_PLACES = ['header', 'cookie']

    blacklist = set()

    def is_blacklisted(jti):
        return jti in blacklist

    _guard.init_app(sanic_app, User, is_blacklisted=is_blacklisted)
    sanic_app.ctx.mail = _mail

    register_tortoise(
        sanic_app,
        db_url='sqlite://:memory:',
        modules={"models": ['__main__']},
        generate_schemas=True,
    )

    # Add users for the example
    @sanic_app.listener('before_server_start')
    async def populate_db(sanic):
        await User.create(username="the_dude",
                          email="the_dude@praetorian.test.io",
                          password=_guard.hash_password("abides"),
                          roles="admin",)

        await User.create(username="Donnie",
                          email="donnie@praetorian.test.io",
                          password=_guard.hash_password("iamthewalrus"),
                          roles="operator",)

    # Set up some routes for the example
    @sanic_app.route("/login", methods=["POST"])
    async def login(request):
        """
        Logs a user in by parsing a POST request containing user credentials and
        issuing a JWT token.
        .. example::
           $ curl http://localhost:8000/login -X POST \
             -d '{"username":"Walter","password":"calmerthanyouare"}'
        """
        req = request.json
        username = req.get("username", None)
        password = req.get("password", None)
        user = await _guard.authenticate(username, password)
        ret = {"access_token": await _guard.encode_token(user)}
        return json(ret, status=200)

    @sanic_app.route("/protected")
    @sanic_praetorian.auth_required
    async def protected(request):
        """
        A protected endpoint. The auth_required decorator will require a header
        containing a valid JWT
        .. example::
           $ curl http://localhost:8000/protected -X GET \
             -H "Authorization: Bearer <your_token>"
        """
        user = await sanic_praetorian.current_user()
        return json({"message": f"protected endpoint (allowed user {user.username})"})

    @sanic_app.route('/blacklist_token', methods=['POST'])
    @sanic_praetorian.auth_required
    @sanic_praetorian.roles_required('admin')
    async def blacklist_token(request):
        """
        Blacklists an existing JWT by registering its jti claim in the blacklist.
        .. example::
           $ curl http://localhost:5000/blacklist_token -X POST \
             -d '{"token":"<your_token>"}'
        """
        req = request.json
        data = await _guard.extract_token(req['token'])
        blacklist.add(data['jti'])
        return json({"message": f"token blacklisted ({req['token']})"})

    return sanic_app


# Run the example
if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=8000, workers=1, debug=True)

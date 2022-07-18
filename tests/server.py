from sys import path as sys_path
from os import path as os_path
sys_path.insert(0, os_path.join(os_path.dirname(os_path.abspath(__file__)), ".."))

import sanic_praetorian

from models import User

from sanic import Sanic, json
from sanic.log import logger

from tortoise.contrib.sanic import register_tortoise

from sanic_praetorian import Praetorian
from sanic_praetorian.exceptions import PraetorianError
from sanic_mailing import Mail


_guard = Praetorian()
_mail = Mail()


def create_app(db_path=None):
    """
    Initializes the sanic app for the test suite. Also prepares a set of routes
    to use in testing with varying levels of protections
    """
    sanic_app = Sanic('sanic-testing')
    # In order to process more requests after initializing the app,
    # we have to set degug to false so that it will not check to see if there
    # has already been a request before a setup function
    sanic_app.state.mode = 'Mode.DEBUG'
    sanic_app.config.TESTING = True
    sanic_app.config['PYTESTING'] = True
    sanic_app.config.SECRET_KEY = "top secret"

    sanic_app.config.MAIL_SERVER = 'localhost:25'
    sanic_app.config.MAIL_USERNAME = ''
    sanic_app.config.MAIL_PASSWORD = ''
    sanic_app.config.MAIL_FROM = 'fake@fake.com'
    sanic_app.config.JWT_PLACES = ['header', 'cookie']

    sanic_app.config.FALLBACK_ERROR_FORMAT = "json"

    _guard.init_app(sanic_app, User)
    sanic_app.ctx.mail = _mail

    @sanic_app.route("/unprotected")
    def unprotected(request):
        return json({'message': "success"})

    @sanic_app.route("/kinda_protected")
    @sanic_praetorian.auth_accepted
    async def kinda_protected(request):
        try:
            authed_user = await sanic_praetorian.current_user()
            return json({"message": "success", "user": authed_user.username})
        except PraetorianError:
            return json({"message": "success", "user": None})

    @sanic_app.route("/protected")
    @sanic_praetorian.auth_required
    async def protected(request):
        return json({"message": "success"})

    @sanic_app.route("/protected_admin_required")
    @sanic_praetorian.auth_required
    @sanic_praetorian.roles_required("admin")
    async def protected_admin_required(request):
        return json({"message": "success"})

    @sanic_app.route("/protected_admin_and_operator_required")
    @sanic_praetorian.auth_required
    @sanic_praetorian.roles_required("admin", "operator")
    async def protected_admin_and_operator_required(request):
        return json({"message": "success"})

    @sanic_app.route("/protected_admin_and_operator_accepted")
    @sanic_praetorian.auth_required
    @sanic_praetorian.roles_accepted("admin", "operator")
    async def protected_admin_and_operator_accepted(request):
        return json({"message": "success"})

    @sanic_app.route("/undecorated_admin_required")
    @sanic_praetorian.roles_required("admin")
    async def undecorated_admin_required(request):
        return json({"message": "success"})

    @sanic_app.route("/undecorated_admin_accepted")
    @sanic_praetorian.roles_accepted("admin")
    async def undecorated_admin_accepted(request):
        return json({"message": "success"})

    @sanic_app.route("/reversed_decorators")
    @sanic_praetorian.roles_required("admin", "operator")
    @sanic_praetorian.auth_required
    async def reversed_decorators(request):
        return json({"message": "success"})

    @sanic_app.route("/registration_confirmation")
    def reg_confirm(request):
        return json({"message": "fuck"})

    if not db_path:
        db_path = 'sqlite://:memory:'
    logger.info(f'App db_path: {db_path}')
    register_tortoise(
        sanic_app,
        db_url=db_path,
        modules={"models": ['models']},
        generate_schemas=True,
    )

    return sanic_app


if __name__ == "__main__":
    _app = create_app()
    _app.run(host="127.0.0.1", port=8000, workers=1, debug=True)
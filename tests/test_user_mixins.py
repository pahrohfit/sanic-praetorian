from tortoise import fields
import sanic_beskar
from sanic_beskar.base import Beskar
import sanic_beskar.exceptions
import pytest

from models import NoRolesMixinUser


class TestUserMixin:
    async def test_basic(self, app, mixin_user_class, mock_users):
        mixin_guard = sanic_beskar.Beskar(app, mixin_user_class)

        the_dude = await mock_users(username="the_dude",
                                    password="abides",
                                    guard_name=mixin_guard,
                                    class_name=mixin_user_class)

        assert await mixin_guard.authenticate("the_dude", "abides") == the_dude
        with pytest.raises(sanic_beskar.exceptions.AuthenticationError):
            await mixin_guard.authenticate("the_bro", "abides")
        with pytest.raises(sanic_beskar.exceptions.AuthenticationError):
            await mixin_guard.authenticate("the_dude", "is_undudelike")
        await the_dude.delete()
    
    async def test_no_rolenames(self, app, mixin_user_class, mock_users):
        mixin_guard = sanic_beskar.Beskar(app, mixin_user_class)

        the_noroles_dude = await NoRolesMixinUser.create(
                username="the_noroles_dude",
                email="the_noroles_dude@mock.com",
                password=mixin_guard.hash_password("the_noroles_dude_pw"),
                is_active=True,
        )

        assert the_noroles_dude.rolenames == []
        await the_noroles_dude.delete()
    
    async def test_lookups(self, app, mixin_user_class, mock_users):
        mixin_guard = sanic_beskar.Beskar(app, mixin_user_class)

        the_dude = await mock_users(username="the_dude",
                                    password="abides",
                                    email="the_dude@mock.com",
                                    guard_name=mixin_guard,
                                    class_name=mixin_user_class)


        assert await mixin_user_class.lookup(email="the_dude@mock.com") == the_dude
        assert await mixin_user_class.lookup(username="the_dude") == the_dude
        assert await mixin_user_class.lookup() == None
        assert await mixin_user_class.identify(id=the_dude.id) == the_dude
        assert await mixin_user_class.identify(id=99999999) == None
        await the_dude.delete()

    async def test_totp(self, app, totp_user_class, mock_users):
        totp_guard = sanic_beskar.Beskar(app, totp_user_class)

        the_dude = await mock_users(username="the_dude",
                                    password="abides",
                                    guard_name=totp_guard,
                                    class_name=totp_user_class,
                                    totp='mock')
        assert the_dude.totp == 'mock'
        assert app.config.get('BESKAR_TOTP_ENFORCE', True) is True

        # good creds, missing TOTP
        with pytest.raises(sanic_beskar.exceptions.AuthenticationError) as e:
            await totp_guard.authenticate("the_dude", "abides")
        assert e.type is sanic_beskar.exceptions.TOTPRequired

        # bad creds
        with pytest.raises(sanic_beskar.exceptions.AuthenticationError) as e:
            await totp_guard.authenticate("the_dude", "is_undudelike")
        assert e.type is not sanic_beskar.exceptions.TOTPRequired

        # bad token
        with pytest.raises(sanic_beskar.exceptions.AuthenticationError):
            await totp_guard.authenticate_totp("the_dude", 80085)

        # good creds, bad token
        with pytest.raises(sanic_beskar.exceptions.AuthenticationError) as e:
            await totp_guard.authenticate("the_dude", "abides", 80085)
        assert e.type is not sanic_beskar.exceptions.TOTPRequired

        # bad creds, bad token
        with pytest.raises(sanic_beskar.exceptions.AuthenticationError) as e:
            await totp_guard.authenticate("the_dude", "is_undudelike", 80085)
        assert e.type is not sanic_beskar.exceptions.TOTPRequired

        """
        Verify its ok to call `authenticate` w/o a `token`, for a required user,
            while `BESKAR_TOTP_ENFORCE` is set to `False`
        """
        app.config.BESKAR_TOTP_ENFORCE = False
        _totp_optional_guard = Beskar(app, totp_user_class)
        # good creds, missing TOTP
        _optional_the_dude = await _totp_optional_guard.authenticate("the_dude", "abides")
        assert _optional_the_dude == the_dude

        await the_dude.delete()

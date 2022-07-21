from sanic_praetorian.base import Praetorian
from sanic_praetorian.exceptions import PraetorianError
from sanic_praetorian.decorators import (
    auth_required,
    auth_accepted,
    roles_required,
    roles_accepted,
)
from sanic_praetorian.utilities import (
    current_user,
    current_user_id,
    current_rolenames,
    current_custom_claims,
    generate_totp_qr,
)

from sanic_praetorian.orm.tortoise_user_mixins import TortoiseUserMixin
from sanic_praetorian.orm.umongo_user_mixins import UmongoUserMixin


__all__ = [
    "Praetorian",
    "PraetorianError",
    "auth_required",
    "auth_accepted",
    "roles_required",
    "roles_accepted",
    "current_user",
    "current_user_id",
    "generate_totp_qr",
    "current_rolenames",
    "current_custom_claims",
    "TortoiseUserMixin",
    "UmongoUserMixin",
]

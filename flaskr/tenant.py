from flask import (
    Blueprint, flash, g, redirect, request, session, url_for, jsonify, abort, make_response
)
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.keystone.authconn import KeystoneAuthConn
from flaskr.error_handler import Unauthorized, BadRequest, ServerError


bp = Blueprint('tenants', __name__, url_prefix='/tenants')
authconn = KeystoneAuthConn()

DEFAULT_CONTROLLER_IP = '0.0.0.0'
DEFAULT_CONTROLLER_PORT = 12345


@bp.route('/', methods=(['GET']))
def list_tenants():
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        tentats = authconn.get_project_list(user_token)
        return jsonify(tentats)
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)


@bp.route('/', methods=(['POST']))
def create_tenant():
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        tentats = authconn.create_project({}, user_token)
        return jsonify(tentats)
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)


@bp.route('/<tenant_id>', methods=(['POST']))
def update_tenant(tenant_id):
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        tentats = authconn.update_project(tenant_id, {}, user_token)
        return jsonify(tentats)
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

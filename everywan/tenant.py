from flask import (
    Blueprint, flash, g, redirect, request, session, url_for, jsonify, abort, make_response
)
from werkzeug.security import check_password_hash, generate_password_hash
from everywan.keystone.authconn import KeystoneAuthConn
from everywan.error_handler import Unauthorized, BadRequest, ServerError
from everywan import ctrl_nb_interface

bp = Blueprint('tenants', __name__, url_prefix='/tenants')
authconn = KeystoneAuthConn()

DEFAULT_CONTROLLER_IP = '0.0.0.0'
DEFAULT_CONTROLLER_PORT = 54321


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


@bp.route('/<tenant_id>', methods=(['DELETE']))
def delete_tenant(tenant_id):
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        authconn.delete_project(tenant_id, user_token)
        ctrl_nb_interface.remove_tenant("")
        return jsonify()
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

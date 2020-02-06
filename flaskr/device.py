from flask import (
    Blueprint, flash, g, redirect, request, session, url_for, jsonify, abort, make_response
)
from srv6_sdn_control_plane.northbound.grpc import nb_grpc_client
from flaskr.keystone.authconn import KeystoneAuthConn
from flaskr.error_handler import Unauthorized, BadRequest, ServerError

bp = Blueprint('devices', __name__, url_prefix='/devices')
authconn = KeystoneAuthConn()

DEFAULT_CONTROLLER_IP = '0.0.0.0'
DEFAULT_CONTROLLER_PORT = 12345


@bp.route('/', methods=(['GET']))
def list_devices():
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        return jsonify([])
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)


@bp.route('/<device_id>', methods=(['POST']))
def configure_device(device_id):
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        return jsonify({})
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

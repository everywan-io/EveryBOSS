from flask import (
    Blueprint, flash, g, redirect, request, session, url_for, jsonify, abort, make_response
)
from flaskr.keystone.authconn import KeystoneAuthConn
from flaskr.error_handler import Unauthorized, BadRequest, ServerError
from srv6_sdn_control_plane.northbound.grpc import nb_grpc_client


# from flaskr.db import get_db

bp = Blueprint('overlay_nets', __name__, url_prefix='/overlay_nets')
authconn = KeystoneAuthConn()

DEFAULT_CONTROLLER_IP = '0.0.0.0'
DEFAULT_CONTROLLER_PORT = 12345


@bp.route('/', methods=(['GET']))
def list_overlay_nets():
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        o_nets = []
        return jsonify(o_nets)
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)


@bp.route('/', methods=(['POST']))
def create_overlay_net():
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        o_net = {}
        return jsonify(o_net)
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)


@bp.route('/<overaly_net_id>', methods=(['DELETE']))
def delete_overlay_net(overaly_net_id):
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        o_net = {}
        return jsonify({})
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

from flask import (
    Blueprint, flash, g, redirect, request, session, url_for, jsonify, abort, make_response
)
from everywan.keystone.authconn import KeystoneAuthConn
from everywan.error_handler import Unauthorized, BadRequest, ServerError
from everywan import ctrl_nb_interface

# from everywan.db import get_db

bp = Blueprint('overlay_nets', __name__, url_prefix='/overlay_nets')
authconn = KeystoneAuthConn()

DEFAULT_CONTROLLER_IP = '0.0.0.0'
DEFAULT_CONTROLLER_PORT = 54321


@bp.route('/', methods=(['GET']))
def list_overlay_nets():
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        tenantid = 1  # user_token['project_id']
        limit = request.args.get('limit', default=20, type=int)
        offset = request.args.get('offset', default=0, type=int)

        o_nets = ctrl_nb_interface.get_overlays()
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
        tenantid = 1
        request_dict = request.json
        name_overlay = request_dict.get('name')
        type_overlay = request_dict.get('type')
        interfaces = request_dict.get('interfaces', [])
        encap = request_dict.get('encap')
        o_net = ctrl_nb_interface.create_overlay(name_overlay, type_overlay, interfaces, tenantid, encap)
        return jsonify({})
    except KeyError as e:
        print(e)
        abort(400, description=e)
    except BadRequest as e:
        print(e)
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)


@bp.route('/<overaly_net_id>', methods=(['DELETE']))
def delete_overlay_net(overaly_net_id):
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        tenantid = 1
        ctrl_nb_interface.remove_overlay(overaly_net_id, tenantid)
        return jsonify({})
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

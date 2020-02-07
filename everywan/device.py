from flask import (
    Blueprint, flash, g, redirect, request, session, url_for, jsonify, abort, make_response
)
from everywan.keystone.authconn import KeystoneAuthConn
from everywan.error_handler import Unauthorized, BadRequest, ServerError

from everywan import mongodb_client, ctrl_nb_interface
import everywan.utils as EWUtil
import json
from bson import json_util

bp = Blueprint('devices', __name__, url_prefix='/devices')
authconn = KeystoneAuthConn()


@bp.route('/', methods=(['GET']))
def list_devices():
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        tenantid = 1  # user_token['project_id']
        limit = request.args.get('limit', default=20, type=int)
        offset = request.args.get('offset', default=0, type=int)
        devices = mongodb_client.db.devices.find(
            {'tenantid': tenantid}).skip(offset).limit(limit)
        return jsonify(EWUtil.mongo_cursor_to_json(devices))
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
        tenantid = 1
        request_dict = request.json
        ctrl_nb_interface.configure_device(
            device_id=device_id,
            tenantid=tenantid,
            device_name=request_dict.get('name', ''),
            device_description=request_dict.get('description', ''),
            interfaces=request_dict.get('interfaces', [])
        )
        return jsonify({})
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

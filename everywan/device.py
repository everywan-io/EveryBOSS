#  Copyright 2020 Francesco Lombardo
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from flask import (
    Blueprint, flash, g, redirect, request, session, url_for, jsonify, abort, make_response
)
from everywan.keystone.authconn import KeystoneAuthConn
from everywan.error_handler import Unauthorized, BadRequest, ServerError, ResourceNotFound

from everywan import mongodb_client, ctrl_nb_interface
import everywan.utils as EWUtil
import json
from bson import json_util
from flask_cors import CORS
from srv6_sdn_proto.status_codes_pb2 import NbStatusCode

bp = Blueprint('devices', __name__, url_prefix='/devices')
authconn = KeystoneAuthConn()


@bp.route('/', methods=(['GET']))
def list_devices():
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        tenantid = "1"  # user_token['project_id']
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


@bp.route('/<device_id>', methods=(['GET']))
def get_device(device_id):
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        tenantid = "1"  # user_token['project_id']
        device = mongodb_client.db.devices.find_one(
            {'deviceid': device_id, 'tenantid': tenantid}, {'_id': 0})
        if not device:
            raise ResourceNotFound
        return jsonify(device)
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ResourceNotFound as e:
        abort(404, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)


@bp.route('/<device_id>', methods=(['POST']))
def configure_device(device_id):
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        tenantid = "1"  # user_token['project_id']
        request_dict = request.json
        code, reason = ctrl_nb_interface.configure_device(
            device_id=device_id,
            tenantid=tenantid,
            device_name=request_dict.get('name', ''),
            device_description=request_dict.get('description', ''),
            interfaces=request_dict.get('interfaces', [])
        )
        if code == NbStatusCode.INTERNAL_SERVER_ERROR or code == NbStatusCode.STATUS_SERVICE_UNAVAILABLE:
            raise ServerError(description=reason)
        elif code == NbStatusCode.BAD_REQUEST:
            raise BadRequest(description=reason)
        elif code == NbStatusCode.UNAUTHORIZED:
            raise Unauthorized(description=reason)
        return jsonify({})
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)


@bp.route('/<device_id>/enable', methods=(['POST']))
def enable_device(device_id):
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        tenantid = "1"  # user_token['project_id']
        code, reason = ctrl_nb_interface.enable_device(
            deviceid=device_id, tenantid=tenantid)
        if code == NbStatusCode.INTERNAL_SERVER_ERROR or code == NbStatusCode.STATUS_SERVICE_UNAVAILABLE:
            raise ServerError(description=reason)
        elif code == NbStatusCode.BAD_REQUEST:
            raise BadRequest(description=reason)
        elif code == NbStatusCode.UNAUTHORIZED:
            raise Unauthorized(description=reason)
        return jsonify({})
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)


@bp.route('/<device_id>/disable', methods=(['POST']))
def disable_device(device_id):
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        tenantid = "1"  # user_token['project_id']
        code, reason = ctrl_nb_interface.disable_device(
            deviceid=device_id, tenantid=tenantid)
        if code == NbStatusCode.INTERNAL_SERVER_ERROR or code == NbStatusCode.STATUS_SERVICE_UNAVAILABLE:
            raise ServerError(description=reason)
        elif code == NbStatusCode.BAD_REQUEST:
            raise BadRequest(description=reason)
        elif code == NbStatusCode.UNAUTHORIZED:
            raise Unauthorized(description=reason)
        return jsonify({})
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

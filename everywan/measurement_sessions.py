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
    Blueprint, flash, g, redirect, request, session, url_for, jsonify, abort, make_response,
)
from bson.objectid import ObjectId
from everywan import mongodb_client, ctrl_nb_interface
from everywan.error_handler import Unauthorized, BadRequest, ServerError
from everywan.keystone.authconn import KeystoneAuthConn
import everywan.utils as EWUtil
import json
import urllib
from srv6_sdn_proto.status_codes_pb2 import NbStatusCode

# from everywan.db import get_db

bp = Blueprint('measurement_sessions', __name__, url_prefix='/measurement_sessions')
#authconn = KeystoneAuthConn()

@bp.route('/', methods=(['GET']))
def list_measurement_sessions():
    try:
        #user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        #tenantid = "1"  # user_token['project_id']
        #limit = request.args.get('limit', default=20, type=int)
        #offset = request.args.get('offset', default=0, type=int)
        #o_nets = mongodb_client.db.measurement.find(
        #    {'tenantid': tenantid}).skip(offset).limit(limit)
        #return jsonify(EWUtil.mongo_cursor_to_json(o_nets))
        with open('datiMeasurementSessions.json', "r") as fileJson:
            data = json.load(fileJson)
        return jsonify(data)
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

@bp.route('/<measurement_sessions_id>', methods=(['GET']))
def get_measurement_session(measurement_sessions_id):
    try:
        #user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        #tenantid = "1"  # user_token['project_id']
        #o_net = mongodb_client.db.overlays.find_one(
        #    {'tenantid': tenantid, '_id': ObjectId(measurement_sessions_id)})
        #return jsonify(EWUtil.id_to_string(o_net))
        counter = 0
        with open('datiMeasurementSessions.json', "r") as fileJson:
            data = json.load(fileJson)
        for elemento in data:
            if(int(elemento['sessionId']) == int(measurement_sessions_id)):
                counter = 1
                return elemento
        if(counter == 0):
            return "Resource not found... no 'sessionId' matches 'id: " + measurement_sessions_id + "'"
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

@bp.route('/<measurement_sessions_id>', methods=(['PUT']))
def run_stop_measurement_session(measurement_sessions_id):
    try:
        #user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        #tenantid = "1"  # user_token['project_id']
        #o_net = mongodb_client.db.overlays.find_one(
        #    {'tenantid': tenantid, '_id': ObjectId(measurement_sessions_id)})
        #return jsonify(EWUtil.id_to_string(o_net))
        sessione = measurement_sessions_id;
        return ("{}");
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

@bp.route('/<measurement_sessions_id>', methods=(['DELETE']))
def delete_measurement_session(measurement_sessions_id):
    try:
        #user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        #tenantid = user_token['project_id']
        #tenantid = "1"  # user_token['project_id']
        #code, reason = ctrl_nb_interface.remove_overlay(overlay_net_id, tenantid)
        #if code == NbStatusCode.STATUS_INTERNAL_SERVER_ERROR or code == NbStatusCode.STATUS_SERVICE_UNAVAILABLE:
        #    raise ServerError(description=reason)
        #elif code == NbStatusCode.STATUS_BAD_REQUEST:
        #    raise BadRequest(description=reason)
        #elif code == NbStatusCode.STATUS_UNAUTHORIZED:
        #    raise Unauthorized(description=reason)
        sessione = measurement_sessions_id;
        return jsonify({});
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

@bp.route('/', methods=(['POST']))
def create_measurement_session():
    try:
        #user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        #tenantid = "1"  # user_token['project_id']
        #o_net = mongodb_client.db.overlays.find_one(
        #    {'tenantid': tenantid, '_id': ObjectId(measurement_sessions_id)})
        #return jsonify(EWUtil.id_to_string(o_net))
        return ("{}");
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

@bp.route('/<measurement_sessions_id>/results', methods=(['GET']))
def get_measurement_sessions_results(measurement_sessions_id):
    try:
        #user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        #tenantid = "1"  # user_token['project_id']
        #o_net = mongodb_client.db.overlays.find_one(
        #    {'tenantid': tenantid, '_id': ObjectId(measurement_sessions_id)})
        #return jsonify(EWUtil.id_to_string(o_net))
        counter = 0
        with open('ResultsMeasurementSessions.json', "r") as fileJson:
            data = json.load(fileJson)
        for elemento in data:
            if(int(elemento['sessionId']) == int(measurement_sessions_id)):
                counter = 1
                return elemento
        if(counter == 0):
            return "Resource not found... no 'sessionId' matches 'id: " + measurement_sessions_id + "'"
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

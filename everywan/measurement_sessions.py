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
from everywan.error_handler import Unauthorized, BadRequest, ServerError, ResourceNotFound
from everywan.keystone.authconn import KeystoneAuthConn
import everywan.utils as EWUtil
import json
import urllib
from srv6_sdn_proto.status_codes_pb2 import NbStatusCode
from srv6_sdn_control_plane.northbound.grpc.nb_grpc_client import STAMPError

# from everywan.db import get_db

bp = Blueprint('measurement_sessions', __name__, url_prefix='/measurement_sessions')
authconn = KeystoneAuthConn()

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

        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        request_dict = request.json
        try:
            sessions = ctrl_nb_interface.get_stamp_sessions()
        except STAMPError as err:
            raise BadRequest(description=err.msg)
        return jsonify([{
            'sessionId': session['ssid'],
            'sessionDescription': session['description'],
            'senderName': session['sender_name'],
            'reflectorName': session['reflector_name'],
            'status': session['status'].capitalize(),
            'delayDirectPath': session['average_delay_direct_path'],
            'delayReturnPath': session['average_delay_return_path'],
            'interval': session['interval'],
            'authenticationMode': session['auth_mode'].capitalize(),
            'keyChain': session['key_chain'] if session['key_chain'] != '' else None,
            'timestampFormat': session['timestamp_format'].upper(),
            'delayMeasurementMode': session['delay_measurement_mode'].capitalize().replace('-', ' '),
            'sessionReflectorMode': session['session_reflector_mode'].capitalize(),
            'senderDeviceId': session['sender_id'],
            'senderStampIp': session['sender_source_ip'],
            'reflectorDeviceId': session['reflector_id'],
            'reflectorStampIp': session['reflector_source_ip'],
            'sidlist': session['direct_sidlist'],
            'returnSidlist': session['return_sidlist'],
            'results': '',
            'overlayId': '',
            'overlayName': ''
            } for session in sessions]
        )
        
        #with open('datiMeasurementSessions.json', "r") as fileJson:
        #    data = json.load(fileJson)
        #return jsonify(data)
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

        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        request_dict = request.json
        try:
            sessions = ctrl_nb_interface.get_stamp_sessions(ssid=int(measurement_sessions_id))
            if len(sessions) == 0:
                raise ResourceNotFound
        except STAMPError as err:
            raise BadRequest(description=err.msg)
        session = sessions[0]
        return jsonify({
            'sessionId': session['ssid'],
            'sessionDescription': session['description'],
            'senderName': session['sender_name'],
            'reflectorName': session['reflector_name'],
            'status': session['status'].capitalize(),
            'delayDirectPath': session['average_delay_direct_path'],
            'delayReturnPath': session['average_delay_return_path'],
            'interval': session['interval'],
            'authenticationMode': session['auth_mode'].capitalize(),
            'keyChain': session['key_chain'] if session['key_chain'] != '' else None,
            'timestampFormat': session['timestamp_format'].upper(),
            'delayMeasurementMode': session['delay_measurement_mode'].capitalize().replace('-', ' '),
            'sessionReflectorMode': session['session_reflector_mode'].capitalize(),
            'senderDeviceId': session['sender_id'],
            'senderStampIp': session['sender_source_ip'],
            'reflectorDeviceId': session['reflector_id'],
            'reflectorStampIp': session['reflector_source_ip'],
            'sidlist': session['direct_sidlist'],
            'returnSidlist': session['return_sidlist'],
            'results': '',
            'overlayId': '',
            'overlayName': ''
            }
        )

        # counter = 0
        # with open('datiMeasurementSessions.json', "r") as fileJson:
        #     data = json.load(fileJson)
        # for elemento in data:
        #     if(int(elemento['sessionId']) == int(measurement_sessions_id)):
        #         counter = 1
        #         return elemento
        # if(counter == 0):
        #     return "Resource not found... no 'sessionId' matches 'id: " + measurement_sessions_id + "'"
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

@bp.route('/<measurement_sessions_id>', methods=(['PUT']))
def run_stop_measurement_session(measurement_sessions_id):
    try:
        #user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        #tenantid = "1"  # user_token['project_id']
        #o_net = mongodb_client.db.overlays.find_one(
        #    {'tenantid': tenantid, '_id': ObjectId(measurement_sessions_id)})
        #return jsonify(EWUtil.id_to_string(o_net))

        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        request_dict = request.json
        command = request_dict.get('command', None)

        try:
            if command == 'start':
                ctrl_nb_interface.start_stamp_session(ssid=int(measurement_sessions_id))
            elif command == 'stop':
                ctrl_nb_interface.stop_stamp_session(ssid=int(measurement_sessions_id))
            else:
                raise BadRequest(description=f'Invalid command: {command}')
        except STAMPError as err:
            raise BadRequest(description=err.msg)

        return ("{}")

        #sessione = measurement_sessions_id;
        #return ("{}");
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

        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        try:
            ctrl_nb_interface.destroy_stamp_session(ssid=int(measurement_sessions_id))
        except STAMPError as err:
            raise BadRequest(description=err.msg)

        return jsonify({})
        # sessione = measurement_sessions_id;
        # return jsonify({});
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

        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        request_dict = request.json
        sender_id = request_dict.get('sessionSenderDeviceId', None)
        reflector_id = request_dict.get('sessionReflectorDeviceId', None)
        direct_sidlist = request_dict.get('sidlist', None)
        if direct_sidlist is not None:
            direct_sidlist = direct_sidlist.split(',')
        return_sidlist = request_dict.get('returnSidlist', None)
        if return_sidlist is not None:
            return_sidlist = return_sidlist.split(',')
        interval = request_dict.get('interval', None)
        auth_mode = request_dict.get('authenticationMode', None)
        if auth_mode is not None:
            auth_mode = auth_mode.lower()
        key_chain = request_dict.get('keyChain', None)
        timestamp_format = request_dict.get('timestampFormat', None)
        if timestamp_format is not None:
            timestamp_format = timestamp_format.lower()
        #packet_loss_type = request_dict.get('', None)
        packet_loss_type = None
        delay_measurement_mode = request_dict.get('delayMeasurementMode', None)
        if delay_measurement_mode is not None:
            delay_measurement_mode = delay_measurement_mode.lower().replace(' ', '-')
        session_reflector_mode = request_dict.get('sessionReflectorMode', None)
        if session_reflector_mode is not None:
            session_reflector_mode = session_reflector_mode.lower()
        #sender_source_ip = request_dict.get('', None)
        sender_source_ip = None
        #reflector_source_ip = request_dict.get('', None)
        reflector_source_ip = None
        #description = request_dict.get('', None)
        description = None
        duration = request_dict.get('duration', 0)
        if duration is None:
            duration = 0
        #overlayName
        #overlaySession
        #sessionSender
        #sessionReflector
        run_after_creation = request_dict.get('runOptions', 'no').lower()
        run_after_creation = True if run_after_creation == 'yes' else False

        try:
            ctrl_nb_interface.create_stamp_session(
                sender_id=sender_id,
                reflector_id=reflector_id,
                direct_sidlist=direct_sidlist, return_sidlist=return_sidlist,
                interval=interval, auth_mode=auth_mode,
                key_chain=key_chain, timestamp_format=timestamp_format,
                packet_loss_type=packet_loss_type,
                delay_measurement_mode=delay_measurement_mode,
                session_reflector_mode=session_reflector_mode,
                sender_source_ip=sender_source_ip,
                reflector_source_ip=reflector_source_ip, description=description,
                duration=duration,
                start_after_creation=run_after_creation
            )
        except STAMPError as err:
            raise BadRequest(description=err.msg)

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
        
        
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        request_dict = request.json
        try:
            results = ctrl_nb_interface.get_stamp_results(ssid=int(measurement_sessions_id))
            if len(results) == 0:
                raise ResourceNotFound
        except STAMPError as err:
            raise BadRequest(description=err.msg)
        result = results[0]
        return jsonify({
            'sessionId': result['ssid'],
            'sidlist': result['direct_sidlist'],
            'returnSidlist': result['return_sidlist'],
            'type': result['measurement_type'],
            'direction': result['measurement_direction'],
            'results': {
                'delayDirectPath': {
                    'delays': [{
                        'id': delay['id'],
                        'timestamp': delay['timestamp'],
                        'value': delay['value']
                    } for delay in result['results']['direct_path']['delays']],
                    'averageDelay': result['results']['direct_path']['average_delay'],
                },
                'delayReturnPath': {
                    'delays': [{
                        'id': delay['id'],
                        'timestamp': delay['timestamp'],
                        'value': delay['value']
                    } for delay in result['results']['return_path']['delays']],
                    'averageDelay': result['results']['return_path']['average_delay'],
                },
            }
        })

        # counter = 0
        # with open('ResultsMeasurementSessions.json', "r") as fileJson:
        #     data = json.load(fileJson)
        # for elemento in data:
        #     if(int(elemento['sessionId']) == int(measurement_sessions_id)):
        #         counter = 1
        #         return elemento
        # if(counter == 0):
        #     return "Resource not found... no 'sessionId' matches 'id: " + measurement_sessions_id + "'"
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


@bp.route('/sidlists', methods=(['GET']))
def get_sid_lists():
    try:
        #user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        #tenantid = "1"  # user_token['project_id']
        #limit = request.args.get('limit', default=20, type=int)
        #offset = request.args.get('offset', default=0, type=int)
        #o_nets = mongodb_client.db.measurement.find(
        #    {'tenantid': tenantid}).skip(offset).limit(limit)
        #return jsonify(EWUtil.mongo_cursor_to_json(o_nets))

        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        tenantid = '1'  # user_token['project_id']
        sender_id = request.args.get('senderId', type=str)
        reflector_id = request.args.get('reflectorId', type=str)
        if sender_id is None:
            raise BadRequest(description='Missing mandatory param "senderId"')
        if reflector_id is None:
            raise BadRequest(description='Missing mandatory param "reflectorId"')
        code, reason, sid_lists = ctrl_nb_interface.get_sid_lists(
            ingress_deviceid=sender_id, egress_deviceid=reflector_id,
            tenantid=tenantid)
        if code == NbStatusCode.STATUS_INTERNAL_SERVER_ERROR or code == NbStatusCode.STATUS_SERVICE_UNAVAILABLE:
            raise ServerError(description=reason)
        elif code == NbStatusCode.STATUS_BAD_REQUEST:
            raise BadRequest(description=reason)
        elif code == NbStatusCode.STATUS_UNAUTHORIZED:
            raise Unauthorized(description=reason)
        return jsonify(sid_lists)
        
        #with open('datiMeasurementSessions.json', "r") as fileJson:
        #    data = json.load(fileJson)
        #return jsonify(data)
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

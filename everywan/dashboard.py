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

bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')
authconn = KeystoneAuthConn()


@bp.route('/', methods=(['GET']))
def dashboard():
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        tenantid = user_token['project_id']
        # tenantid = "1"  # user_token['project_id']
        result = {
            'operators': {'total': 1},
            'tenants': {},
            'overlays': {'total': 0},
            'devices': {'total': 0}
        }

        devices_tot = mongodb_client.db.devices.find(
            {'tenantid': tenantid}).count()
        if devices_tot is not None:
            result['devices']['total'] = devices_tot

        devices_enab = mongodb_client.db.devices.find(
            {'tenantid': tenantid, 'enabled': True}).count()
        if devices_enab is not None:
            result['devices']['enabled'] = devices_enab

        devices_conf = mongodb_client.db.devices.find(
            {'tenantid': tenantid, 'configured': True}).count()
        if devices_conf is not None:
            result['devices']['configured'] = devices_conf

        devices_conn = mongodb_client.db.devices.find(
            {'tenantid': tenantid, 'connected': True}).count()
        if devices_conn is not None:
            result['devices']['connected'] = devices_conn

        o_nets = mongodb_client.db.overlays.find(
            {'tenantid': tenantid}).count()
        if o_nets:
            result['overlays']['total'] = o_nets

        return jsonify(result)
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

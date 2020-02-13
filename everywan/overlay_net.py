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
from bson.objectid import ObjectId
from everywan import mongodb_client, ctrl_nb_interface
from everywan.error_handler import Unauthorized, BadRequest, ServerError
from everywan.keystone.authconn import KeystoneAuthConn
import everywan.utils as EWUtil

# from everywan.db import get_db

bp = Blueprint('overlay_nets', __name__, url_prefix='/overlay_nets')
authconn = KeystoneAuthConn()


@bp.route('/', methods=(['GET']))
def list_overlay_nets():
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        tenantid = "1"  # user_token['project_id']
        limit = request.args.get('limit', default=20, type=int)
        offset = request.args.get('offset', default=0, type=int)
        o_nets = mongodb_client.db.overlays.find(
            {'tenantid': tenantid}).skip(offset).limit(limit)
        return jsonify(EWUtil.mongo_cursor_to_json(o_nets))
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)


@bp.route('/<overaly_net_id>', methods=(['GET']))
def get_overlay_net(overaly_net_id):
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        tenantid = "1"  # user_token['project_id']
        o_net = mongodb_client.db.overlays.find_one(
            {'tenantid': tenantid, '_id': ObjectId(overaly_net_id)})
        return jsonify(EWUtil.id_to_string(o_net))
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
        # tenantid = user_token['project_id']
        tenantid = "1"  # user_token['project_id']
        request_dict = request.json
        name_overlay = request_dict.get('name')
        type_overlay = request_dict.get('type')
        interfaces = request_dict.get('interfaces', [])
        tunnel_type = request_dict.get('tunnel_type')
        o_net = ctrl_nb_interface.create_overlay(
            name_overlay, type_overlay, interfaces, tenantid, tunnel_type)
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
        #tenantid = user_token['project_id']
        tenantid = "1"  # user_token['project_id']
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


@bp.route('/<overaly_net_id>/slices', methods=(['post']))
def assign_slice_ovarlay(overaly_net_id):
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        # tenantid = user_token['project_id']
        tenantid = "1"  # user_token['project_id']
        request_dict = request.json
        slice_name = request_dict.get('name')
        interfaces = request_dict.get('interfaces', [])
        ctrl_nb_interface.assign_slice_to_overlay(slice_name, tenantid, interfaces)
        return jsonify({})
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

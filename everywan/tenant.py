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
from werkzeug.security import check_password_hash, generate_password_hash
from everywan.keystone.authconn import KeystoneAuthConn
from everywan.error_handler import Unauthorized, BadRequest, ServerError, TenantNotFound
from everywan import mongodb_client, ctrl_nb_interface

bp = Blueprint('tenants', __name__, url_prefix='/tenants')
authconn = KeystoneAuthConn()


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


@bp.route('/<tenant_id>', methods=(['GET']))
def get_tenant(tenant_id):
    try:
        tenant = {}
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        project = authconn.get_project(tenant_id, user_token)
        if (project):
            # tenant_id = '1'
            tenant = mongodb_client.db.tenants.find_one(
                {'tenantid': tenant_id}, {'_id': 0})
            if tenant:
                tenant['domain_id'] = project.domain_id
                tenant['name'] = project.name
                return jsonify(tenant)
        raise TenantNotFound(tenant_id=tenant_id)
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except TenantNotFound as e:
        abort(404, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)


@bp.route('/<tenant_id>', methods=(['POST']))
def update_tenant(tenant_id):
    try:
        user_token = authconn.validate_token(request.headers['X-Auth-Token'])
        request_dict = request.json
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

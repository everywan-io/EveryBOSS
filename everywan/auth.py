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
from everywan.error_handler import Unauthorized, BadRequest, ServerError
# from everywan.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')
authconn = KeystoneAuthConn()


@bp.route('/signin', methods=(['POST']))
def login():
    try:
        request_dict = request.json
        username = request_dict['username']
        password = request_dict['password']
        project = request_dict['project_id'] if 'project_id' in request_dict else None
        domain = request_dict['domain'] if 'domain' in request_dict else None
        user_token = authconn.authenticate(
            username, password, project, domain)
        user = authconn.get_user(
            user_id=user_token['user_id'], user_token=user_token)
        user_body = {
            "token_type": "X-Auth-Token",
            "expires_in": user_token['expires'],
            "access_token": user_token['token'],
            "user": {
                "locale": "it",
                "id": user.id,
                "username": user.name,
                "domain_id": user.domain_id,
                "project_id": user_token['project_id'],
                "project_name": user_token['project_name']
            }
        }
        return jsonify(user_body)
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)


@bp.route('/signout', methods=(['GET']))
def logout():
    try:
        return make_response('', 202)
    except KeyError as e:
        abort(400, description=e)
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

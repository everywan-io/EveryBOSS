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
from everywan.error_handler import ResourceNotFound, Unauthorized, BadRequest, ServerError, Conflict, UserNotFound, TenantNotFound
import re
import hashlib
import time
from everywan import mongodb_client, ctrl_nb_interface
from srv6_sdn_proto.status_codes_pb2 import NbStatusCode


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
        abort(400, description=f'Missing parameter {e}')
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


@bp.route('/signup', methods=(['POST']))
def signup():
    try:
        request_dict = request.json
        username = request_dict['username']
        password = request_dict['password']
        confirm_password = request_dict['confirm_password']  # TODO: implement confirm password
        email = request_dict['email']
        project = request_dict['project_id'] if 'project_id' in request_dict else None
        domain = request_dict['domain'] if 'domain' in request_dict else None

        # Validate field lengths
        if len(username) > 30 or len(username) < 6:
            raise BadRequest(
                description='Invalid username. Username should be 6–30 characters long'
            )
        if len(email) > 40:
            raise BadRequest(
                description='Invalid email. Email should be < 40 characters long'
            )
        if len(password) > 30 or len(password) < 6:
            raise BadRequest(
                description='Invalid password. Password should be 6–30 characters long'
            )
        if len(domain) > 30 or len(domain) < 6:
            raise BadRequest(
                description='Invalid domain name. Domain should be 6–30 characters long'
            )

        if password != confirm_password:
            raise BadRequest(
                description='Password and Confirm Password does not match'
            )

        email_format: str = r"(^[a-zA-Z0-9'_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"

        if re.match(email_format, email, re.IGNORECASE) is None:
            raise BadRequest(
                description=f'Invalid email: {email}'
            )

        try:
            domain_info = authconn.create_domain({'name': domain})
        except Conflict:
            raise Conflict(
                description="Domain name already registered. Please try with another one."
            )

        try:
            project_info = authconn.create_project(
                {
                    'name': domain,
                    'domain': domain_info.id
                }
            )
        except Conflict:
            authconn.delete_domain(domain_id=domain_info.id)
            raise Conflict(
                description="Domain name already registered. Please try with another one."
            )
        except Exception:
            authconn.delete_domain(domain_id=domain_info.id)
            raise Unauthorized()

        try:
            user_info = authconn.create_user(
                {
                    'name': username,
                    'domain': domain_info.id,
                    'password': password,
                    'email': email,
                    'project': project_info.id
                }
            )
        except Conflict:
            authconn.delete_project(project_id=project_info.id)
            authconn.delete_domain(domain_id=domain_info.id)
            raise Conflict(
                description="Username already registered. Please try with another one."
            )
        except Exception:
            authconn.delete_project(project_id=project_info.id)
            authconn.delete_domain(domain_id=domain_info.id)
            raise Unauthorized()

        try:
            authconn.grant_role(
                role='user',
                user=user_info.id,
                project=project_info.id
            )
        except Exception:
            authconn.delete_user(user_id=user_info.id)
            authconn.delete_project(project_id=project_info.id)
            authconn.delete_domain(domain_id=domain_info.id)
            raise Unauthorized()

        token = hashlib.sha256(str(time.time()).encode()).hexdigest()

        mongodb_client.db.tenants.insert(
            {
                'tenantid': project_info.id,
                'token': token
            }
        )

        code, reason = ctrl_nb_interface.configure_tenant(
            tenantid=project_info.id, tenant_info='', vxlan_port=40000
        )
        if code == NbStatusCode.STATUS_INTERNAL_SERVER_ERROR or code == NbStatusCode.STATUS_SERVICE_UNAVAILABLE:
            raise ServerError(description=reason)
        elif code == NbStatusCode.STATUS_BAD_REQUEST:
            raise BadRequest(description=reason)
        elif code == NbStatusCode.STATUS_UNAUTHORIZED:
            raise Unauthorized(description=reason)

        # TODO: aggiungere associazione project-user
        # Generare token
        # Creare config per tenant nel database mongodb

        user_body = {
            "user": {
                "locale": "it",
                "id": user_info.id,
                "username": user_info.name,
                "domain_id": user_info.domain_id,
                "project_id": project_info.id,
                "project_name": project_info.name
            }
        }

        return jsonify(user_body), 201
    except KeyError as e:
        abort(400, description=f'Missing parameter {e}')
    except BadRequest as e:
        abort(400, description=e.description)
    except Unauthorized as e:
        abort(401, description=e.description)
    except Conflict as e:
        abort(409, description=e.description)
    except ServerError as e:
        abort(500, description=e.description)

# TODO: accessible only to the admins
# @bp.route('/signup', methods=(['DELETE']))
# def del_user():
#     try:
#         request_dict = request.json
#         username = request_dict['username']
#         # password = request_dict['password']
#         # confirm_password = request_dict['password']  # TODO: implement confirm password
#         # email = request_dict['email']
#         # project = request_dict['project_id'] if 'project_id' in request_dict else None
#         domain_name = request_dict['domain'] if 'domain' in request_dict else None

#         #user = authconn.get_user({'name': username, 'domain': domain}, None)
#         #user = authconn.get_user(username, None)
#         #project = authconn.get_project(project)

#         domains = authconn.keystone.domains.list(name=domain_name)
#         if domains is None or len(domains) == 0:
#             raise TenantNotFound(domain_name)
#         domain = domains[0]
#         print('dom, ', domain)

#         project = authconn.keystone.projects.find(name=domain_name, domain=domain.id)
#         if project is None:
#             raise TenantNotFound(domain_name)
#         print(project)

#         users = authconn.keystone.users.list(name=username, domain=domain.id, default_project=project.id)
#         if users is None or len(users) == 0:
#             raise UserNotFound(username)
#         user = users[0]
#         print('user',   user)

#         # user = authconn.get_user_by_name(username, domain, domain)
#         # print('user', user)

#         authconn.delete_user(user_id=user.id)
#         authconn.delete_project(project_id=domain.id)
#         #authconn.delete_domain(domain_id=project.id)

#         mongodb_client.db.tenants.delete_one(
#              {
#                  'tenantid': project.id
#              }
#          )

#         return '', 204

#         # if password != confirm_password:
#         #     raise BadRequest(
#         #         description='Password and Confirm Password does not match'
#         #     )

#         # email_format: str = r"(^[a-zA-Z0-9'_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"

#         # if re.match(email_format, email, re.IGNORECASE) is None:
#         #     raise BadRequest(
#         #         description=f'Invalid email: {email}'
#         #     )

#         # try:
#         #     domain_info = authconn.create_domain({'name': domain})
#         # except Conflict:
#         #     raise Conflict(
#         #         description="Domain name already registered. Please try with another one."
#         #     )

#         # try:
#         #     project_info = authconn.create_project(
#         #         {
#         #             'name': domain,
#         #             'domain': domain_info.id
#         #         }
#         #     )
#         # except Conflict:
#         #     authconn.delete_domain(domain_id=domain_info.id)
#         #     raise Conflict(
#         #         description="Domain name already registered. Please try with another one."
#         #     )
#         # except Exception:
#         #     authconn.delete_domain(domain_id=domain_info.id)
#         #     raise Unauthorized()

#         # try:
#         #     user_info = authconn.create_user(
#         #         {
#         #             'name': username,
#         #             'domain': domain_info.id,
#         #             'password': password,
#         #             'email': email,
#         #             'project': project_info.id
#         #         }
#         #     )
#         # except Conflict:
#         #     authconn.delete_project(project_id=project_info.id)
#         #     authconn.delete_domain(domain_id=domain_info.id)
#         #     raise Conflict(
#         #         description="Username already registered. Please try with another one."
#         #     )
#         # except Exception:
#         #     authconn.delete_project(project_id=project_info.id)
#         #     authconn.delete_domain(domain_id=domain_info.id)
#         #     raise Unauthorized()

#         # try:
#         #     authconn.grant_role(
#         #         role='user',
#         #         user=user_info.id,
#         #         project=project_info.id
#         #     )
#         # except Exception:
#         #     authconn.delete_user(user_id=user_info.id)
#         #     authconn.delete_project(project_id=project_info.id)
#         #     authconn.delete_domain(domain_id=domain_info.id)
#         #     raise Unauthorized()

#         # token = hashlib.sha256(str(time.time()).encode()).hexdigest()

#         # mongodb_client.db.tenants.insert(
#         #     {
#         #         'tenantid': project_info.id,
#         #         'token': token
#         #     }
#         # )

#         # code, reason = ctrl_nb_interface.configure_tenant(
#         #     tenantid=project_info.id, tenant_info='', vxlan_port=40000
#         # )
#         # if code == NbStatusCode.STATUS_INTERNAL_SERVER_ERROR or code == NbStatusCode.STATUS_SERVICE_UNAVAILABLE:
#         #     raise ServerError(description=reason)
#         # elif code == NbStatusCode.STATUS_BAD_REQUEST:
#         #     raise BadRequest(description=reason)
#         # elif code == NbStatusCode.STATUS_UNAUTHORIZED:
#         #     raise Unauthorized(description=reason)

#         # # TODO: aggiungere associazione project-user
#         # # Generare token
#         # # Creare config per tenant nel database mongodb

#         # user_body = {
#         #     "user": {
#         #         "locale": "it",
#         #         "id": user_info.id,
#         #         "username": user_info.name,
#         #         "domain_id": user_info.domain_id,
#         #         "project_id": project_info.id,
#         #         "project_name": project_info.name
#         #     }
#         # }

#         # return jsonify(user_body), 201
#     except KeyError as e:
#         abort(400, description=f'Missing parameter {e}')
#     except BadRequest as e:
#         abort(400, description=e.description)
#     except Unauthorized as e:
#         abort(401, description=e.description)
#     except ResourceNotFound as e:
#         abort(404, description=e.description)
#     except UserNotFound as e:
#         abort(404, description=e.description)
#     except TenantNotFound as e:
#         abort(404, description=e.description)
#     except Conflict as e:
#         abort(409, description=e.description)
#     except ServerError as e:
#         abort(500, description=e.description)

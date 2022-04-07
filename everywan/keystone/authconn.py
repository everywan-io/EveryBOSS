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

from keystoneauth1.identity import v3
from keystoneauth1 import session, exceptions
from keystoneclient.v3 import client
from keystone.exception import UserNotFound, DomainNotFound
from http import HTTPStatus
from everywan.error_handler import Unauthorized, Conflict, BadRequest
from everywan import KEYSTONE_HOST, KEYSTONE_PORT
import logging


class KeystoneAuthConn:

    def __init__(self, config=None):
        self.logger = logging.getLogger("KeystoneAuthConn")
        self.config = config
        self.auth_url = "http://" + KEYSTONE_HOST + ":" + str(KEYSTONE_PORT) + "/v3"
        self.endpoint = "http://" + KEYSTONE_HOST + ":35357/v3"
        self.admin_user_domain_name = "Default"
        self.admin_project_name = "admin"
        self.admin_username = "admin"
        self.admin_password = "12345678"
        self.admin_project_domain_name = "Default"
        self.auth = v3.Password(auth_url=self.auth_url, username=self.admin_username, password=self.admin_password, project_domain_name=self.admin_project_domain_name,
                                project_name=self.admin_project_name, user_domain_name=self.admin_user_domain_name)
        self.sess = session.Session(auth=self.auth)
        self.keystone = client.Client(session=self.sess, endpoint=self.endpoint, endpoint_override=self.endpoint)

    def authenticate(self, user_name, password, project_id=None, domain=None):
        """
        Authenticate a user using username/password, plus project
        :param user: user: name, id or None
        :param password: password or None
        :param project_id: id, or None. If None first found project will be used to get an scope token
        :return: the scoped token info or raises an exception. The token is a dictionary with:
            token:  token string id,
            username: username,
            project_id: scoped_token project_id,
            project_name: scoped_token project_name,
            expires: epoch time when it expires,

        """
        try:
            auth_token = {}
            if (project_id is None):
                unscoped_auth = self.keystone.get_raw_token_from_identity_service(
                    auth_url=self.auth_url, username=user_name, password=password, user_domain_name=domain, project_domain_name=domain)

                project_list = self.keystone.projects.list(
                    user=unscoped_auth["user"]["id"])
                if not project_list:
                    auth_token = {
                        "token": unscoped_auth.auth_token,
                        "user_id": unscoped_auth.user_id,
                        "username": unscoped_auth.username,
                        "expires": unscoped_auth.expires.timestamp(),
                        "issued_at": unscoped_auth.issued.timestamp()
                    }
                    return auth_token
                project_id = project_list[0].id

            scoped_auth = self.keystone.get_raw_token_from_identity_service(
                auth_url=self.auth_url, username=user_name, password=password, project_id=project_id, user_domain_name=domain, project_domain_name=domain)

            auth_token = {
                "token": scoped_auth.auth_token,
                "user_id": scoped_auth.user_id,
                "username": scoped_auth.username,
                "project_id": scoped_auth.project_id,
                "project_name": scoped_auth.project_name,
                "expires": scoped_auth.expires.timestamp(),
                "issued_at": scoped_auth.issued.timestamp()
            }

            return auth_token
        except exceptions.http.Unauthorized:
            raise Unauthorized('Wrong domain, username or password')
        except Exception as e:
            print(e)
            raise Unauthorized()

    def validate_token(self, token):
        """
        Check if the token is valid.

        :param token: token to validate
        :return: dictionary with information associated with the token. If the
        token is not valid, returns None.
        """
        if not token:
            return

        try:
            token_info = self.keystone.tokens.validate(token=token)
            token_info_ = {
                "token": token_info["auth_token"],
                "project_id": token_info["project"]["id"],
                "project_name": token_info["project"]["name"],
                "user_id": token_info["user"]["id"],
                "username": token_info["user"]["name"],
                "expires": token_info.expires.timestamp(),
                "issued_at": token_info.issued.timestamp()
            }

            return token_info_
        except Exception as e:
            raise Unauthorized()

    def revoke_token(self, user_token):
        """
        Revoke a token.

        :param token: token to be revoked
        """
        try:
            self.logger.info("Revoking token: " + user_token)
            self.keystone.tokens.revoke_token(token=user_token['token'])

            return True
        except Exception as e:
            raise Unauthorized()

    def create_user(self, user_info):
        """
        Create a user.

        :param user_info: full user info.
        :raises KeystoneAuthConnOperationException: if user creation failed.
        """
        try:
            user = self.keystone.users.create(
                name=user_info['name'],
                domain=user_info.get('domain', None),
                password=user_info.get('password', None),
                email=user_info.get('email', None),
                description=user_info.get('description', None),
                default_project=user_info.get('project', None)
            )
            return user
        except exceptions.http.Conflict:
            raise Conflict()
        except exceptions.http.BadRequest as err:
            raise BadRequest(str(err))
        except Exception as e:
            raise Unauthorized()

    def update_user(self, user_info):
        """
        Change the user name and/or password.

        :param user_info:  user info modifications
        :raises KeystoneAuthConnNotImplementedException: if function not implemented
        """
        raise NotImplementedError("The method is not implemented")

    def delete_user(self, user_id):
        """
        Delete user.

        :param user_id: user identifier.
        :raises KeystoneAuthConnOperationException: if user deletion failed.
        """
        try:
            result, detail = self.keystone.users.delete(user_id)
            if result.status_code != 204:
                raise ClientException(
                    "error {} {}".format(result.status_code, detail))

            return True
        except Exception as e:
            raise Unauthorized()

    def get_user_list(self, user_token):
        """
        Get user list.

        :param user_token: dictionary to filter user list by name (username is also admited) and/or _id
        :return: returns a list of users.
        """
        try:
            users = self.keystone.projects.list(user=user_token["user_id"])
            return users
        except Exception as e:
            raise Unauthorized()

    def get_user(self, user_id, user_token):
        """
        Get one user
        :param user:  id or name
        :return: dictionary with the user information
        """
        try:
            user = self.keystone.users.get(user_id)
            return user
        except Exception as e:
            raise Unauthorized()

    def create_project(self, project_info):
        """
        Create a project.

        :param project_info: full project info.
        :return: the internal id of the created project
        :raises KeystoneAuthConnOperationException: if project creation failed.
        """
        try:
            project = self.keystone.projects.create(
                name=project_info['name'],
                domain=project_info['domain'],
                description=project_info.get('description', None)
            )
            return project
        except exceptions.http.Conflict:
            raise Conflict()
        except exceptions.http.BadRequest as err:
            raise BadRequest(str(err))
        except Exception as e:
            raise Unauthorized()

    def delete_project(self, project_id):
        """
        Delete a project.

        :param project_id: project identifier.
        :raises KeystoneAuthConnOperationException: if project deletion failed.
        """
        try:
            self.keystone.projects.update(project_id, enabled=False)
            result, detail = self.keystone.projects.delete(project_id)
            if result.status_code != 204:
                raise ClientException(
                    "error {} {}".format(result.status_code, detail))

            return True
        except Exception as e:
            raise Unauthorized()

    def get_project_list(self, user_token):
        """
        Get all the projects.
        :param user_token: dictionary to filter user list by name (username is also admited) and/or _id
        :return: list of projects
        """
        try:
            user = None
            if user_token:
                user = user_token["user_id"]
            projects = self.keystone.projects.list(user=user)
            print(projects)
            projects = [{
                "name": project.name,
                "_id": project.id,
                "domain_id": project.domain_id
            } for project in projects]

            return projects
        except Exception as e:
            self.logger.exception(e)
            raise Unauthorized()

    def get_project(self, project, user_token):
        """
        Get one project
        :param project:  project id or project name
        :return: dictionary with the project information
        """
        try:
            proj = self.keystone.projects.get(project=project)
            return proj
        except Exception as e:
            self.logger.exception(e)
            raise Unauthorized()

    def update_project(self, project_id, project_info, user_token):
        """
        Change the information of a project
        :param project_id: project to be changed
        :param project_info: full project info
        :return: None
        """
        raise NotImplementedError("The method is not implemented")

    def create_domain(self, domain_info):
        """
        Create a domain.

        :param domain_info: full domain info.
        :return: the internal id of the created domain
        :raises KeystoneAuthConnOperationException: if domain creation failed.
        """
        try:
            domain = self.keystone.domains.create(
                name=domain_info['name'],
                description=domain_info.get('description', None)
            )
            return domain
        except exceptions.http.Conflict:
            raise Conflict()
        except exceptions.http.BadRequest as err:
            raise BadRequest(str(err))
        except Exception as e:
            raise Unauthorized()

    def delete_domain(self, domain_id):
        """
        Delete a domain.

        :param domain_id: domain identifier.
        :raises KeystoneAuthConnOperationException: if domain deletion failed.
        """
        try:
            self.keystone.domains.update(domain_id, enabled=False)
            result, detail = self.keystone.domains.delete(domain_id)
            if result.status_code != 204:
                raise ClientException(
                    "error {} {}".format(result.status_code, detail))

            return True
        except Exception as e:
            raise Unauthorized()

    def get_domain_list(self, user_token):
        """
        Get all the domains.
        :param user_token: dictionary to filter user list by name (username is also admited) and/or _id
        :return: list of domains
        """
        try:
            user = None
            if user_token:
                user = user_token["user_id"]
            domains = self.keystone.domains.list(user=user)
            print(domains)
            domains = [{
                "name": domain.name,
                "_id": domain.id,
                "domain_id": domain.domain_id
            } for domain in domains]

            return domains
        except Exception as e:
            self.logger.exception(e)
            raise Unauthorized()

    def get_domain(self, domain, user_token):
        """
        Get one domain
        :param domain:  domain id or domain name
        :return: dictionary with the domain information
        """
        try:
            proj = self.keystone.domains.get(domain=domain)
            return proj
        except Exception as e:
            self.logger.exception(e)
            raise Unauthorized()

    def update_domain(self, domain_id, domain_info, user_token):
        """
        Change the information of a domain
        :param domain_id: domain to be changed
        :param domain_info: full domain info
        :return: None
        """
        raise NotImplementedError("The method is not implemented")

    def grant_role(self, role, user=None, domain=None, project=None):
        try:
            role = self.keystone.roles.list(name=role)[0]
            self.keystone.roles.grant(
                role=role.id, user=user, domain=domain, project=project
            )
        except Exception as e:
            self.logger.exception(e)
            raise Unauthorized()

    def get_user_by_name(self, name, domain, project):
        """
        Get one project
        :param project:  project id or project name
        :return: dictionary with the project information
        """
        try:
            user = self.keystone.users.list(default_project=project, domain=domain, name=name)
            return user
        except Exception as e:
            self.logger.exception(e)
            raise Unauthorized()

    def get_project_by_userid(self, userid):
        """
        Get one project
        :param project:  project id or project name
        :return: dictionary with the project information
        """
        try:
            proj = self.keystone.projects.get(project=project)
            return proj
        except Exception as e:
            self.logger.exception(e)
            raise Unauthorized()

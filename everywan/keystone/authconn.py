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
from keystoneauth1 import session
from keystoneclient.v3 import client
from http import HTTPStatus
from everywan.error_handler import Unauthorized
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
        self.keystone = client.Client(session=self.sess, endpoint=self.endpoint)

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
        raise NotImplementedError("The method is not implemented")

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
        raise NotImplementedError("The method is not implemented")

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

    def create_project(self, project_info, user_token):
        """
        Create a project.

        :param project_info: full project info.
        :return: the internal id of the created project
        :raises KeystoneAuthConnOperationException: if project creation failed.
        """
        raise NotImplementedError("The method is not implemented")

    def delete_project(self, project_id, user_token):
        """
        Delete a project.

        :param project_id: project identifier.
        :raises KeystoneAuthConnOperationException: if project deletion failed.
        """
        try:
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

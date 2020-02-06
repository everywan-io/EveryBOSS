from flask import make_response, jsonify


def init_errorhandler(app):
    @app.errorhandler(400)
    def bad_request(error):
        return make_response(jsonify({'error': error.description}), 400)

    @app.errorhandler(401)
    def unauthorized(error):
        return make_response(jsonify({'error': error.description}), 401)

    @app.errorhandler(404)
    def not_found(error):
        return make_response(jsonify({'error': error.description}), 404)

    @app.errorhandler(500)
    def server_error(error):
        return make_response(jsonify({'error': error.description}), 500)


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class ResourceNotFound(Error):
    def __init__(self):
        self.description = 'Resource not found.'


class TenantNotFound(Error):
    def __init__(self, tenant_id=None):
        self.description = 'Tenant {0} not found.'.format(tenant_id)


class UserNotFound(Error):
    def __init__(self, user_id=None):
        self.description = 'User {0} not found.'.format(user_id)


class Unauthorized(Error):
    def __init__(self):
        self.description = 'Unauthorized'


class BadRequest(Error):
    def __init__(self, description=None):
        if description is not None:
            self.description = description
        else:
            self.description = 'Malformed request'


class ServerError(Error):
    def __init__(self, description=None):
        if description is not None:
            self.description = description
        else:
            self.description = 'Server Error'

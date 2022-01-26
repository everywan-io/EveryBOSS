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

import os
from flask import Flask, jsonify
from flask_cors import CORS
from flask_pymongo import PyMongo
from .error_handler import init_errorhandler
from srv6_sdn_control_plane.northbound.grpc import nb_grpc_client

DEFAULT_CONTROLLER_IP = os.environ.get('CONTROLLER_IP', '127.0.0.1')
DEFAULT_CONTROLLER_PORT = int(os.environ.get('CONTROLLER_PORT', 54321))
KEYSTONE_HOST = os.environ.get('KEYSTONE_HOST', '0.0.0.0')
KEYSTONE_PORT = int(os.environ.get('KEYSTONE_PORT', 35357))

MONGODB_HOST = os.environ.get('MONGODB_HOST', 'localhost')
MONGODB_PORT = int(os.environ.get('MONGODB_PORT', 27017))
MONGODB_USERNAME = os.environ.get('MONGODB_USERNAME', 'root')
MONGODB_PASSWORD = int(os.environ.get('MONGODB_PASSWORD', '12345678'))

mongodb_client = PyMongo()
ctrl_nb_interface = nb_grpc_client.NorthboundInterface(
    DEFAULT_CONTROLLER_IP, DEFAULT_CONTROLLER_PORT)


def create_app(test_config=None):
    from . import auth
    from . import device
    from . import operator
    from . import overlay_net
    from . import tenant
    from . import dashboard
    from . import measurement_sessions

    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'everywan.sqlite'),
    )
    CORS(app, resources={r"/.*": {"origins": "*"}})
    app.config['CORS_HEADERS'] = 'Content-Type'
    app.config["MONGO_URI"] = "mongodb://" + MONGODB_USERNAME + ":" + MONGODB_PASSWORD + "@" + MONGODB_HOST + ":" + str(MONGODB_PORT) + "/EveryWan?authSource=admin&readPreference=primary&appname=NBI&ssl=false"
    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)
    init_errorhandler(app)
    mongodb_client.init_app(app)
    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    app.register_blueprint(dashboard.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(device.bp)
    app.register_blueprint(operator.bp)
    app.register_blueprint(overlay_net.bp)
    app.register_blueprint(measurement_sessions.bp)
    app.register_blueprint(tenant.bp)

    return app

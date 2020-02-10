import os
from flask import Flask
from flask_cors import CORS
from flask_pymongo import PyMongo
from .error_handler import init_errorhandler
from srv6_sdn_control_plane.northbound.grpc import nb_grpc_client

DEFAULT_CONTROLLER_IP = '0.0.0.0'
DEFAULT_CONTROLLER_PORT = 54321

mongodb_client = PyMongo()
ctrl_nb_interface = nb_grpc_client.NorthboundInterface(
    DEFAULT_CONTROLLER_IP, DEFAULT_CONTROLLER_PORT)


def create_app(test_config=None):
    from . import auth
    from . import device
    from . import operator
    from . import overlay_net
    from . import tenant

    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'everywan.sqlite'),
    )
    CORS(app)
    app.config["MONGO_URI"] = "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=NBI&ssl=false"
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

    app.register_blueprint(auth.bp)
    app.register_blueprint(device.bp)
    app.register_blueprint(operator.bp)
    app.register_blueprint(overlay_net.bp)
    app.register_blueprint(tenant.bp)

    return app

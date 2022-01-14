#!/usr/bin/env bash

export FLASK_APP=everywan
export FLASK_ENV=development

export CONTROLLER_IP=127.0.0.1
export CONTROLLER_PORT=54321

flask run --port=8080 --host=0.0.0.0
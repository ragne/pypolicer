#!/usr/bin/python
"""
Api for accessing user records and post new.
"""

from flask import Flask, request, g
from flask_restful import Api, abort, Resource
from flask_restful.reqparse import RequestParser
from flask_cors import CORS

from .db import GlobalState
from .checks import Checks, BasicCheck
from .utils import settings

import os

app = Flask(__name__)
api = Api(app)
CORS(app)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))  # refers to application_top
app.config['WERKZEUG_DEBUG_PIN'] = 'off'
app.config['TOKEN_EXPIRE_AFTER'] = os.environ.get('POLICER_TOKEN_EXPIRE_AFTER', 3600)
app.config['DEBUG'] = bool(os.environ.get('FLASK_DEBUG', False))

parser = RequestParser(bundle_errors=True)
parser.add_argument('data')


@app.before_request
def get_global_state():
    """Set global state to thread local `g`"""
    g.state = GlobalState(hostname=settings.get('DB.address', '127.0.0.1'))


class PolicerUserList(Resource):
    """
    List all users
    """
    def get(self):
        """List users"""
        return [k for k, _ in g.state.items()]


class ChecksList(Resource):
    """List all checks"""
    def get(self):
        """Return all except abstraction"""
        # @TODO: review leaky abstraction here
        return {v.name: {"schema": v.value.get_schema(), "defaults": v.value.get_defaults()[v.name]}
                for v in Checks if v.value != BasicCheck}


class ChecksSchema(Resource):
    """Returns check schema help text"""
    def get(self, pk):
        """Get schema from pk or return an error"""
        check = Checks.get(pk)
        if check:
            return {pk: check.get_schema()}
        else:
            return {"error": "No check with name %s was found" % pk}, 404


class User(object):
    """Represent a user"""
    def __init__(self, username=None, global_state=None):
        self.username = username
        self.exist = True
        self.gs = global_state or GlobalState(hostname=settings.get('DB.address', '127.0.0.1'))
        self.profile = self.gs.get(self.username, {})
        if not self.profile:
            self.exist = False
            self.set_defaults()

    def __bool__(self):
        return self.exist

    def __eq__(self, other):
        return self.exist == other

    @staticmethod
    def get_all_plugins():
        """Get all checks for user"""
        return {v.name: v.value for v in Checks if v.value != BasicCheck}

    def set_defaults(self):
        """Set defaults to profile"""
        for plugin in self.get_all_plugins().values():
            _settings = plugin.get_defaults()
            for name, options in _settings.items():
                if not self.profile.get(name):
                    self.profile[name] = options

    def save(self):
        """Save user to GlobalState"""
        self.gs[self.username] = self.profile
        self.gs.save()

    def delete(self):
        """Delete user from GlobalState"""
        del self.gs[self.username]
        self.gs.save()


class UserController(Resource):
    """Resource for manipulating user records"""
    def get(self, pk):
        """Return user info, if exists"""
        if pk:
            user = User(username=pk)
            if user:
                return {"user": user.profile, "id": pk}
            else:
                return {"error": "user not found"}, 404
        return {"error": "pk is not specified!"}

    def post(self, pk):
        """Create new user or overwrite exist"""
        args = parser.parse_args(request)
        data = args.get('data')
        if data:
            try:
                data.pop('id')
            except KeyError:
                pass
            user = User(username=pk)

            user.profile.update(data)
            user.save()
            return {"user": user.profile}
        return {"error": "no data found"}

    def delete(self, pk):
        """Delete user record"""
        user = User(username=pk)
        if user:
            return user.delete()
        else:
            return abort(404)


api.add_resource(UserController, '/user/<string:pk>')
api.add_resource(PolicerUserList, '/users', endpoint='list_all_users')
api.add_resource(UserController, '/user/<string:pk>', endpoint='update_user')
api.add_resource(ChecksSchema, '/check/<string:pk>', endpoint='get_check_schema')
api.add_resource(ChecksList, '/checks', endpoint='get_checks_list')

if __name__ == '__main__':
    print("package", __package__)
    app.run(debug=True, host='0.0.0.0', port=7000)

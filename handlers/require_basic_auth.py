import base64

__author__ = 'lionelschinckus'


def require_basic_auth(handler_class):
    def wrap_execute(handler_execute):

        def require_basic_auth(handler, kwargs):
            auth_header = handler.request.headers.get('Authorization')
            if auth_header is None or not auth_header.startswith('Basic '):
                handler.set_status(401)
                handler.set_header('WWW-Authenticate', 'Basic realm=Restricted')
                handler._transforms = []
                handler.finish()
                return False

            auth_decoded = base64.b64decode(bytes(auth_header[6:], encoding="ascii")).decode()
            username, password = auth_decoded.split(':', 2)
            kwargs['basicauth_user'], kwargs['basicauth_pass'] = username, password
            return True

        def _execute(self, transforms, *args, **kwargs):
            if not require_basic_auth(self, kwargs):
                return False
            return handler_execute(self, transforms, *args, **kwargs)

        return _execute

    handler_class._execute = wrap_execute(handler_class._execute)
    return handler_class
from http import HTTPStatus

def application(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [b'Nginx Unit running']

import threading
from werkzeug.serving import make_server
import threading
from . import config, wsgi

_server = None
_thread = None


def start(port: int = None):
    global _server, _thread
    if _server is not None:
        return
    if port is None:
        port = config.UNIT_PORT
    _server = make_server("0.0.0.0", port, wsgi.app)
    _thread = threading.Thread(target=_server.serve_forever, daemon=True)
    _thread.start()


def stop():
    global _server, _thread
    if _server is not None:
        _server.shutdown()
        _thread.join()
        _server = None
        _thread = None


if __name__ == "__main__":
    start()
    try:
        _thread.join()
    except KeyboardInterrupt:
        stop()

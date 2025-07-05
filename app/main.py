import threading
from werkzeug.serving import make_server
import threading
import logging
from . import config, wsgi

logger = logging.getLogger(__name__)

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
    logger.info("Proxy iniciado na porta %s", port)


def stop():
    global _server, _thread
    if _server is not None:
        _server.shutdown()
        _thread.join()
        _server = None
        _thread = None
        logger.info("Proxy parado")


if __name__ == "__main__":
    start()
    try:
        _thread.join()
    except KeyboardInterrupt:
        stop()

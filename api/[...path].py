from backend.server import Handler, _connect, ensure_demo


_connect().close()
ensure_demo()


class handler(Handler):
    pass

from backend.server import Handler, _connect, ensure_demo


class handler(Handler):
    def __init__(self, *args, **kwargs):
        _connect().close()
        ensure_demo()
        super().__init__(*args, **kwargs)

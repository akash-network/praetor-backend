class PraetorException(Exception):
    status_code = 200
    error_code = "P0000"

    def __init__(self, payload=None, error_code=None, status_code=None):
        Exception.__init__(self)
        self.payload = payload
        if error_code is not None:
            self.error_code = error_code
        if status_code is not None:
            self.status_code = status_code

    def to_dict(self):
        rv = dict(self.payload or ())
        return rv

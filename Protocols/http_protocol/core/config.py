class Config:
    def __init__(self):
        self.buffer_size = 10485760
        self.max_body_size = 104857600

_config = Config()

def get_config():
    return _config

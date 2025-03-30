import yaml

class Settings:
    def __init__(self, config_file="config.yaml"):
        self.config_file = config_file
        self.settings = self.load_settings()

    def load_settings(self):
        with open(self.config_file, "r") as file:
            return yaml.safe_load(file)

    def get(self, key, default=None):
        return self.settings.get(key, default)

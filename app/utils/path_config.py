from pathlib import Path
import os


class PathConfig:
    @property
    def base_dir(self):
        return Path(os.getenv("APP_BASE_PATH", Path(__file__).parent.parent.parent))

    @property
    def config_dir(self):
        return self.base_dir / "app" / "config"

    @property
    def template_dir(self):
        return self.config_dir / "idps"

    @property
    def cert_dir(self):
        return self.base_dir / "app" / "certs"


paths = PathConfig()

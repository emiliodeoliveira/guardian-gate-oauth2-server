import importlib.util
import sys
from pathlib import Path

pkg_path = Path(__file__).resolve().parent.parent / '__init__.py'
spec = importlib.util.spec_from_file_location('app_pkg', str(pkg_path))
app_pkg = importlib.util.module_from_spec(spec)
sys.modules['app_pkg'] = app_pkg
spec.loader.exec_module(app_pkg)

app = app_pkg.create_app()
print('create_app() OK, flask app name=' + app.name)


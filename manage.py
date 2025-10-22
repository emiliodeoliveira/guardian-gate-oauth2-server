# Management entrypoint for Flask CLI and migrations.
# This file creates an `app` variable so `flask` can discover the app.
import importlib.util
import sys
from pathlib import Path

pkg_path = Path(__file__).resolve().parent / '__init__.py'
spec = importlib.util.spec_from_file_location('app_pkg', str(pkg_path))
app_pkg = importlib.util.module_from_spec(spec)
sys.modules['app_pkg'] = app_pkg
spec.loader.exec_module(app_pkg)

# create the Flask app instance for Flask CLI / migrations
app = app_pkg.create_app()

if __name__ == '__main__':
    app.run(debug=True)


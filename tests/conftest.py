import os
import tempfile

# Must be set before `app` is imported (module-level config).
os.environ.setdefault("FWX_DATA", tempfile.mkdtemp(prefix="fwx-test-"))
os.environ["FWX_SANDBOX"] = "local"          # tests run without docker; containment is tested via docker_argv()
os.environ["FWX_SALT"] = "test-salt"

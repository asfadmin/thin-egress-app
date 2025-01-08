import os

# Override environment variables that we don't want to be accidentally pulling
# defaults from in tests. These need to be set before app.py is imported by
# pytest in order to ensure that initialization code that runs at import time
# will get the fake values.
os.environ["AUTH_BASE_URL"] = "http://testing-auth-base-url"

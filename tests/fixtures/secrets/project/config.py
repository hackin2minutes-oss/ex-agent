import os

# Fake credentials for a scanner fixture. They are not valid for any service.
AWS_ACCESS_KEY_ID = "AKIAZ7Q3M5XW2KB4RT6N"
DATABASE_URL = "postgres://app:not-a-real-password@db.internal:5432/app"
API_TOKEN = os.environ.get("API_TOKEN", "")

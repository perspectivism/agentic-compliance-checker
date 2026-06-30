# Fixture: hardcoded_secret_app
# Intended GAP evidence for IA-5 (secrets handling).
#
# SAFETY: these are NOT real credentials. The access key below is the
# non-functional example key from AWS's own public documentation, and the
# password is obviously fake. The secret scanner must DETECT these patterns but
# tests must assert that logs/reports MASK the values (never print them in full).

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "hunter2-not-a-real-password"


def connect():
    return {
        "aws_key": AWS_ACCESS_KEY_ID,
        "aws_secret": AWS_SECRET_ACCESS_KEY,
        "db_password": DB_PASSWORD,
    }

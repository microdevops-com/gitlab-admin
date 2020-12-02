#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Import common code
from sysadmws_common import *

import gitlab
import glob
import textwrap
import subprocess
import json
import re
import psycopg2
import datetime

# Constants and envs

LOGO="Settings"
WORK_DIR = "./"
LOG_DIR = "./log"
LOG_FILE = "settings.log"
SETTINGS_YAML = "settings.yaml"

# Custom Exceptions
class SubprocessRunError(Exception):
    pass

# Main

if __name__ == "__main__":

    # Set parser and parse args
    parser = argparse.ArgumentParser(description='{LOGO} functions.'.format(LOGO=LOGO))
    parser.add_argument("--debug", dest="debug", help="enable debug", action="store_true")
    parser.add_argument("--dry-run-gitlab", dest="dry_run_gitlab", help="no new objects created in gitlab", action="store_true")
    parser.add_argument("--yaml", dest="yaml", help="use file FILE instead of default settings.yaml", nargs=1, metavar=("FILE"))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--apply-settings", dest="setup_settings", help="ensure settings created in GitLab, their settings setup", action="store_true")
    args = parser.parse_args()

    # Set logger and console debug
    if args.debug:
        logger = set_logger(logging.DEBUG, LOG_DIR, LOG_FILE)
    else:
        logger = set_logger(logging.ERROR, LOG_DIR, LOG_FILE)

    GL_ADMIN_PRIVATE_TOKEN = os.environ.get("GL_ADMIN_PRIVATE_TOKEN")
    if GL_ADMIN_PRIVATE_TOKEN is None:
        raise Exception("Env var GL_ADMIN_PRIVATE_TOKEN missing")

    PG_DB_HOST = os.environ.get("PG_DB_HOST")
    if PG_DB_HOST is None:
        raise Exception("Env var PG_DB_HOST missing")

    PG_DB_NAME = os.environ.get("PG_DB_NAME")
    if PG_DB_NAME is None:
        raise Exception("Env var PG_DB_NAME missing")

    PG_DB_USER = os.environ.get("PG_DB_USER")
    if PG_DB_USER is None:
        raise Exception("Env var PG_DB_USER missing")

    PG_DB_PASS = os.environ.get("PG_DB_PASS")
    if PG_DB_PASS is None:
        raise Exception("Env var PG_DB_PASS missing")

    # Catch exception to logger

    try:

        logger.info("Starting {LOGO}".format(LOGO=LOGO))

        # Chdir to work dir
        os.chdir(WORK_DIR)

        # Read settings
        if args.yaml is not None:
            settings_yaml_dict = load_yaml("{0}".format(args.yaml[0]), logger)
            if settings_yaml_dict is None:
                raise Exception("Config file error or missing: {0}".format(args.yaml[0]))
        else:
            settings_yaml_dict = load_yaml("{0}/{1}".format(WORK_DIR, SETTINGS_YAML), logger)
            if settings_yaml_dict is None:
                raise Exception("Config file error or missing: {0}/{1}".format(WORK_DIR, SETTINGS_YAML))

        # Connect to PG
        dsn = "host={} dbname={} user={} password={}".format(PG_DB_HOST, PG_DB_NAME, PG_DB_USER, PG_DB_PASS)
        conn = psycopg2.connect(dsn)

        # Do tasks

        if args.setup_settings:

            # Connect to GitLab
            gl = gitlab.Gitlab(settings_yaml_dict["gitlab"]["url"], private_token=GL_ADMIN_PRIVATE_TOKEN)
            gl.auth()

            # Get settings
            settings = gl.settings.get()

            settings_dict = settings_yaml_dict["settings"]
            if not args.dry_run_gitlab:
                settings.signup_enabled = settings_dict["signup_enabled"]
                settings.minimum_password_length = settings_dict["minimum_password_length"]
                settings.require_two_factor_authentication = settings_dict["require_two_factor_authentication"]
                settings.two_factor_grace_period = settings_dict["two_factor_grace_period"]
                settings.user_default_external = settings_dict["user_default_external"]
                settings.auto_devops_enabled = settings_dict["auto_devops_enabled"]
                settings.shared_runners_enabled = settings_dict["shared_runners_enabled"]
                settings.first_day_of_week = settings_dict["first_day_of_week"]
                settings.time_tracking_limit_to_hours = settings_dict["time_tracking_limit_to_hours"]
                settings.save()

            logger.info("Settings:")
            logger.info(settings)

        # Close connection
        conn.close()

    # Reroute catched exception to log
    except Exception as e:
        logger.exception(e)
        logger.error("Finished {LOGO} with errors in file {file}".format(LOGO=LOGO, file=args.yaml[0] if args.yaml is not None else WORK_DIR + "/" + SETTINGS_YAML))
        sys.exit(1)

    logger.info("Finished {LOGO}".format(LOGO=LOGO))

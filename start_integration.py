import sys
import subprocess


try:
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'python_dependencies.txt'])
except Exception as e:
    raise Exception(f'Failed to install package. Exception [{str(e)}]')


import re
import json
import traceback
from sqs_integration import Integration
from integration_log import IntegrationLog, LogLevel
from integration_error import IntegrationError
from jsonschema import validate
from auth_data import OnevizionAuth, AwsAuth
from message_trackor_settings_parser import MessageTrackorSettingsParser


with open('settings.json', "rb") as PFile:
    settings_data = json.loads(PFile.read().decode('utf-8'))

with open('settings_schema.json', "rb") as PFile:
    data_schema = json.loads(PFile.read().decode('utf-8'))

try:
    validate(instance=settings_data, schema=data_schema)
except Exception as e:
    raise Exception("Incorrect value in the settings file\n{}".format(str(e)))

ov_url = re.sub("^https://", "", settings_data["ovUrl"])
ov_integration_name = settings_data["ovIntegrationName"]

ov_auth = OnevizionAuth(ov_url, settings_data["ovAccessKey"], settings_data["ovSecretKey"])
aws_auth = AwsAuth(settings_data["awsAccessKeyId"], settings_data["awsSecretAccessKey"], settings_data["awsRegion"])
queue_url = settings_data["queueUrl"]
wait_time_seconds = settings_data["waitTimeSeconds"]

with open('ihub_parameters.json', "rb") as PFile:
    ihub_data = json.loads(PFile.read().decode('utf-8'))

process_id = ihub_data['processId']

integration_log = IntegrationLog(process_id, ov_auth.url, ov_auth.access_key, ov_auth.secret_key,
                                                ov_integration_name, ov_token=True)

if "createTrackors" in settings_data:
    message_trackors_to_create = MessageTrackorSettingsParser.get_message_trackors(settings_data["createTrackors"], ov_auth, False, integration_log)
if "updateTrackors" in settings_data:
    message_trackors_to_update = MessageTrackorSettingsParser.get_message_trackors(settings_data["updateTrackors"], ov_auth, True, integration_log)

message_trackors = message_trackors_to_create + message_trackors_to_update

sqsIntegration = Integration(integration_log, aws_auth, queue_url, message_trackors, wait_time_seconds)

try:
    sqsIntegration.start()
except IntegrationError as e:
    error_message = str(e.message)
    description = str(e.description)
    integration_log.add(LogLevel.ERROR, error_message, description)
    raise e
except Exception as e:
    error_message = repr(e)
    description = traceback.format_exc()
    integration_log.add(LogLevel.ERROR, error_message, description)
    raise e

###
#
# Lenovo Redfish examples - Update Firmware
#
# Copyright Notice:
#
# Copyright 2019 Lenovo Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
###


import sys
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.auth import HTTPBasicAuth
import redfish
import json
import time
from . import lenovo_utils as utils


def update_firmware(ip, login_account, login_password, image, targets, fsprotocol, fsip, fsport, fsusername, fspassword, fsdir):
    """Update firmware
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params image: Firmware image url
    :type image: string
    :params targets: Targets list
    :type targets: list
    :params fsprotocol: User specified transfer protocol
    :type fsprotocol: string
    :params fsip: User specified file server ip
    :type fsip: string
    :params fsport: User specified file server port
    :type fsport: string
    :params fsusername: User specified file server username
    :type fsusername: string
    :params fspassword: User specified file server password
    :type fspassword: string
    :params fsdir: User specified the image path
    :type fsdir: string
    :returns: returns firmware updating result
    """
    # Connect using the address, account name, and password
    login_host = "https://" + ip
    try:
        # Create a REDFISH object
        result = {}
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result

    try:
        # Get ServiceRoot resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        # Get response_update_service_url
        if response_base_url.status == 200:
            update_service_url = response_base_url.dict['UpdateService']['@odata.id']
        else:
            message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s, \nError message :%s" % ('/redfish/v1', response_base_url.status, message)}
            return result

        response_update_service_url = REDFISH_OBJ.get(update_service_url, None)
        if response_update_service_url.status == 200:
            # Update firmware via local payload
            if fsprotocol.lower() == "httppush" and 'MultipartHttpPushUri' not in response_update_service_url.dict.keys():
                headers = {"Content-Type":"application/octet-stream"}

                firmware_update_url =  login_host + response_update_service_url.dict["HttpPushUri"]
                if os.path.isdir(fsdir):
                    file_path = fsdir + os.sep + image
                else:
                    result = {'ret': False, 'msg': "The path %s doesn't exist, please check the 'fsdir' is correct." %fsdir}
                    return result
                body = {}
                if targets:
                    body["HttpPushUriTargets"] = targets
                    response = REDFISH_OBJ.patch(update_service_url, body=body)
                    if response.status == 200:
                        targets = response.dict["HttpPushUriTargets"]
                        print("HttpPushUriTargets is %s" %targets)
                    else:
                        message = utils.get_extended_error(response)
                        result = {'ret': False, 'msg': "Url '%s' response Error code %s, \nError message :%s" % (
                        firmware_update_url, response.status, message)}
                        return result

                files = {'data-binary':open(file_path,'rb')}
                # Set BMC access credential
                auth = HTTPBasicAuth(login_account, login_password)

                # Get the sessions uri from the session server response
                if utils.g_CAFILE is not None and utils.g_CAFILE != "":
                    firmware_update_response = requests.post(firmware_update_url, headers=headers, auth=auth, files=files, verify=utils.g_CAFILE)
                else:
                    # Ignore SSL Certificates
                    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                    firmware_update_response = requests.post(firmware_update_url, headers=headers, auth=auth, files=files, verify=False)
                response_code = firmware_update_response.status_code
            elif fsprotocol.lower() == 'httppush' and 'MultipartHttpPushUri' in response_update_service_url.dict.keys():
                firmware_update_url = login_host + response_update_service_url.dict['MultipartHttpPushUri']
                if os.path.isdir(fsdir):
                    file_path = fsdir + os.sep +image
                else:
                    result = {'ret':False,'msg':"The path %s doesn't exist, please check the 'fsdir' is correct." %fsdir}
                    return result

                F_image = open(file_path, 'rb')
                if targets:
                    if "BMC-Backup" not in targets[0]:
                        result = {'ret':False,"msg":"If firmware update target is backup image of BMC, please specify targets as BMC-Backup, otherwise targets parameter is needless."}
                        return result
                    multipart_target = login_host + "/redfish/v1/UpdateService/FirmwareInventory/BMC-Backup"
                    BMC_parameters = {'Targets': [multipart_target]}
                    print("MultipartHttpPushUriTargets is %s" % [multipart_target])
                else:
                    multipart_target = ''
                    BMC_parameters = {'Targets': []}
                files = {
                    'UpdateParameters': (multipart_target, json.dumps(BMC_parameters), 'application/json'),
                    'UpdateFile': (image, F_image, 'application/octet-stream')
                }
                # Set BMC access credential
                auth = HTTPBasicAuth(login_account,login_password)

                # Get the sessions uri from the session server response
                if utils.g_CAFILE is not None and utils.g_CAFILE != "":
                    firmware_update_response = requests.post(firmware_update_url,auth=auth,files=files,verify=utils.g_CAFILE)
                else:
                    # Ignore SSL Certificates
                    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                    firmware_update_response = requests.post(firmware_update_url,auth=auth,files=files,verify=False)
                response_code = firmware_update_response.status_code
                F_image.close()
            else:
                firmware_update_url = response_update_service_url.dict['Actions']['#UpdateService.SimpleUpdate']['target']
                # Update firmware via file server
                # Define an anonymous function formatting parameter
                port = (lambda fsport: ":" + fsport if fsport else fsport)
                dir = (lambda fsdir: "/" + fsdir.strip("/") if fsdir else fsdir)
                fsport = port(fsport)
                fsdir = dir(fsdir)

                # Construct image URI by splicing parameters
                if fsprotocol.lower() == "sftp":
                    image_url = fsprotocol.lower() + "://" + fsusername + ":" + fspassword + "@" + fsip + fsport + fsdir + "/" + image
                else:
                    image_url = fsprotocol.lower() + "://" + fsip + fsport + fsdir + "/" + image

                # Build an dictionary to store the request body
                body = {"ImageURI": image_url}

                # Get the user specified parameter
                if targets:
                    body["Targets"] = targets
                if fsprotocol:
                    body["TransferProtocol"] = fsprotocol.upper()
                firmware_update_response = REDFISH_OBJ.post(firmware_update_url, body=body)
                response_code = firmware_update_response.status
            if response_code in [200, 204]:
                result = {'ret': True, 'msg': "Update firmware successfully"}
                return result
            elif response_code == 202:
                if fsprotocol.lower() == "httppush":
                    task_uri = firmware_update_response.json()['@odata.id']
                else:
                    task_uri = firmware_update_response.dict['@odata.id']
                result = task_monitor(REDFISH_OBJ, task_uri)
                # Delete task
                REDFISH_OBJ.delete(task_uri, None)
                if result["ret"] is True:
                    task_state = result["msg"]
                    if task_state == "Completed":
                        result = {'ret': True, 'msg': "Update firmware successfully"}
                    else:
                        result = {'ret': False, 'msg': "Update firmware failed, task state is %s"  %task_state}
                else:
                    return result
            else:
                message = utils.get_extended_error(firmware_update_response)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s, \nError message :%s" % (
                firmware_update_url, response_code, message)}
                return result
        else:
            message = utils.get_extended_error(response_update_service_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s, \nError message :%s" % (update_service_url, response_update_service_url.status, message)}
            return result
    except Exception as e:
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


def flush():
    list = ['|', '\\', '-', '/']
    for i in list:
        sys.stdout.write(' ' * 100 + '\r')
        sys.stdout.flush()
        sys.stdout.write(i + '\r')
        sys.stdout.flush()
        time.sleep(0.1)


def task_monitor(REDFISH_OBJ, task_uri):
    """Monitor task status"""
    RUNNING_TASK_STATE = ["New", "Pending", "Service", "Starting", "Stopping", "Running", "Cancelling", "Verifying"]
    END_TASK_STATE = ["Cancelled", "Completed", "Exception", "Killed", "Interrupted", "Suspended"]
    current_state = ""

    while True:
        response_task_uri = REDFISH_OBJ.get(task_uri, None)
        if response_task_uri.status == 200:
            task_state = response_task_uri.dict["TaskState"]

            if task_state in RUNNING_TASK_STATE:
                if task_state != current_state:
                    current_state = task_state
                    print('Task state is %s, wait a minute' % current_state)
                    continue
                else:
                    flush()
            elif task_state.startswith("Downloading"):
                sys.stdout.write(' ' * 100 + '\r')
                sys.stdout.flush()
                sys.stdout.write(task_state + '\r')
                sys.stdout.flush()
                continue
            elif task_state.startswith("Update"):
                sys.stdout.write(' ' * 100 + '\r')
                sys.stdout.flush()
                sys.stdout.write(task_state + '\r')
                sys.stdout.flush()
                continue
            elif task_state in END_TASK_STATE:
                print("End of the task")
                result = {'ret':True, 'msg': task_state}
                return result
            else:
                result = {"ret":False, "msg":"Task Not conforming to Schema Specification"}
                return result
        else:
            message = utils.get_extended_error(response_task_uri)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s, \nError message :%s" % (task_uri, response_task_uri.status, message)}
            return result


import argparse
def add_helpmessage(argget):
    argget.add_argument('--image', type=str, required=True, help='Specify the fixid of the firmware to be updated.')
    argget.add_argument('--targets', nargs='*', help='Input the targets list')
    argget.add_argument('--fsprotocol', type=str, choices=["SFTP", "TFTP", "HTTPPUSH"], help='Specify the file server protocol.Support:["SFTP", "TFTP", "HTTPPUSH"]')
    argget.add_argument('--fsip', type=str, help='Specify the file server ip.')
    argget.add_argument('--fsport', type=str, default='', help='Specify the file server port')
    argget.add_argument('--fsusername', type=str, help='Specify the file server username.')
    argget.add_argument('--fspassword', type=str, help='Specify the file server password.')
    argget.add_argument('--fsdir', type=str, help='Specify the file server dir to the firmware upload.')

import os
import configparser
def add_parameter():
    """Add update firmware parameter"""
    argget = utils.create_common_parameter_list(example_string='''
    Example of SFTP:
      "python update_firmware.py -i 10.10.10.10 -u USERID -p PASSW0RD --targets https://10.10.10.10/redfish/v1/UpdateService/FirmwareInventory/Slot_7.Bundle --fsprotocol SFTP --fsip 10.10.10.11 --fsusername mysftp --fspassword mypass --fsdir /fspath/ --image lnvgy_fw_sraidmr35_530-50.7.0-2054_linux_x86-64.bin"
    Example of TFTP:
      "python update_firmware.py -i 10.10.10.10 -u USERID -p PASSW0RD --targets https://10.10.10.10/redfish/v1/UpdateService/FirmwareInventory/Slot_7.Bundle --fsprotocol TFTP --fsip 10.10.10.11 --fsdir /fspath/ --image lnvgy_fw_sraidmr35_530-50.7.0-2054_linux_x86-64.bin"
    Example of HTTPPUSH:
      "python update_firmware.py -i 10.10.10.10 -u USERID -p PASSW0RD --fsprotocol HTTPPUSH --fsdir /fspath/ --image lnvgy_fw_sraidmr35_530-50.7.0-2054_linux_x86-64.bin"
    ''')
    add_helpmessage(argget)
    args = argget.parse_args()

    # Get the configuration file name if the user specified
    config_file = args.config

    # Get the common parameter from the configuration files
    config_ini_info = utils.read_config(config_file)

    # Add FileServerCfg parameter to config_ini_info
    cfg = configparser.ConfigParser()
    if os.path.exists(config_file):
        cfg.read(config_file)
        config_ini_info["fsprotocol"] = cfg.get('FileServerCfg', 'FSprotocol')
        config_ini_info["fsip"] = cfg.get('FileServerCfg', 'FSip')
        config_ini_info["fsport"] = cfg.get('FileServerCfg', 'FSport')
        config_ini_info["fsusername"] = cfg.get('FileServerCfg', 'FSusername')
        config_ini_info["fspassword"] = cfg.get('FileServerCfg', 'FSpassword')
        config_ini_info["fsdir"] = cfg.get('FileServerCfg', 'FSdir')

    # Get the user specify parameter from the command line
    parameter_info = utils.parse_parameter(args)
    parameter_info["image"] = args.image
    parameter_info["targets"] = args.targets
    parameter_info['fsprotocol'] = args.fsprotocol
    parameter_info['fsip'] = args.fsip
    parameter_info['fsport'] = args.fsport
    parameter_info['fsusername'] = args.fsusername
    parameter_info['fspassword'] = args.fspassword
    parameter_info['fsdir'] = args.fsdir

    # The parameters in the configuration file are used when the user does not specify parameters
    for key in parameter_info:
        if not parameter_info[key]:
            if key in config_ini_info:
                parameter_info[key] = config_ini_info[key]
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    try:
        image = parameter_info['image']
        targets = parameter_info['targets']
        fsprotocol = parameter_info['fsprotocol']
        fsip = parameter_info['fsip']
        fsport = parameter_info['fsport']
        fsusername = parameter_info['fsusername']
        fspassword = parameter_info['fspassword']
        fsdir = parameter_info['fsdir']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Update firmware result and check result
    result = update_firmware(ip, login_account, login_password, image, targets, fsprotocol, fsip, fsport, fsusername, fspassword, fsdir)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

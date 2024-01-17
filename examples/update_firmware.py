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
import traceback
import lenovo_utils as utils
from urllib.parse import urlparse


def update_firmware(ip, login_account, login_password, image, targets, fsprotocol, fsip, fsport, fsusername, fspassword, fsdir, imageurl=None, applytime="Immediate"):
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
    :params imageurl: User specified the firmware image link
    :type imageurl: string
    :returns: returns firmware updating result
    """
    # Connect using the address, account name, and password
    login_host = "https://" + ip
    try:
        # Create a REDFISH object
        result = {}
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
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
        # Define an anonymous function formatting parameter
        result = check_param(fsprotocol, fsip, fsport, fsdir, image, imageurl, fsusername, fspassword)
        if not result['ret']:
            return result
        else:
            image_info = result['image_info']
        fsprotocol,fsport,fsdir,fsip,image,fsusername,fspassword = image_info
        
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
                # Check whether the current protocol is allowed to update firmware
                simple_update_dict = response_update_service_url.dict['Actions']['#UpdateService.SimpleUpdate']
                if 'TransferProtocol@Redfish.AllowableValues' in simple_update_dict.keys():
                    if fsprotocol not in simple_update_dict['TransferProtocol@Redfish.AllowableValues']:
                        result = {"ret": False, "msg": "%s isn't supported. Supported protocol list: %s." % (
                                    fsprotocol, simple_update_dict['TransferProtocol@Redfish.AllowableValues'])}
                        return result
                # The property VerifyRemoteServerCertificate exists
                if fsprotocol.lower() == "https" and "VerifyRemoteServerCertificate" in response_update_service_url.dict and "RemoteServerCertificates" in response_update_service_url.dict:
                    if response_update_service_url.dict["VerifyRemoteServerCertificate"] is True:
                        remote_url = response_update_service_url.dict["RemoteServerCertificates"]["@odata.id"]
                        remote_response = REDFISH_OBJ.get(remote_url, None)
                        if remote_response.status != 200:
                            message = utils.get_extended_error(remote_response)
                            result = {'ret': False,
                                      'msg': "Url '%s' response Error code %s, \nError message :%s" % (
                                          remote_url, remote_response.status, message)}
                            return result
                        if remote_response.dict["Members@odata.count"] == 0:
                            result = {"ret": False,
                                      "msg": "Target server require certificate verification of HTTPS file server. Please go to 'lenovo_httpfs_certificate_import.py' script to upload the certificate."}
                            return result

                firmware_update_url = simple_update_dict['target']
                # Update firmware via file server


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
                if applytime:
                    body["@Redfish.OperationApplyTime"] = applytime
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
                if applytime and applytime != 'Immediate':
                    task_id = task_uri.split('/')[-1]
                    if applytime == 'OnReset':
                        result = {'ret': True, 'msg': "Update firmware task has been generated ,taskid is '%s', but need to reset system to trigger updating firmware due to applytime is 'OnReset'." % (task_id)}
                    elif applytime == 'OnStartUpdateRequest':
                        result = {'ret': True, 'msg': "Update firmware task has been generated ,taskid is '%s', but need to call the firmware_startupdate.py script to trigger updating firmware due to applytime is 'OnStartUpdateRequest'." % (task_id)}
                    return result
                result = task_monitor(REDFISH_OBJ, task_uri)
                # Delete the task when the task state is completed without any warning
                if result["ret"] is True and "Completed" == result["task_state"] and result['msg'] == '':
                    REDFISH_OBJ.delete(task_uri, None)
                if result["ret"] is True:
                    task_state = result["task_state"]
                    if task_state == "Completed":
                        result['msg'] = 'Update firmware successfully. %s' %(result['msg'])
                    else:
                        result['ret'] = False
                        result['msg'] = 'Update firmware failed. %s' %(result['msg'])
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
        traceback.print_exc()
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


def check_param(fsprotocol, fsip, fsport, fsdir, image, imageurl, fsusername, fspassword):
    """Validation parameters"""
    port = (lambda fsport: ":" + fsport if fsport else fsport)
    dir = (lambda fsdir: "/" + fsdir.strip("/") if fsdir else fsdir)
    if imageurl:
        try:
            url = urlparse(imageurl)  # ParseResult(scheme='https', netloc='fsusername:fspassword@fsip', path='fsdir', params='', query='', fragment='')
            if url.scheme:
                fsprotocol = url.scheme
            if url.netloc:
                fsip = url.netloc
                if "@" in fsip:
                    fsusername, fspassword = fsip.split('@')[0].split(":")
                    fsip = fsip.split("@")[1]
            if url.path:
                image = url.path.split('/')[-1]
                fsdir = url.path.rsplit('/', 1)[0]
        except Exception as e:
            traceback.print_exc()
            return {'ret':False,'msg': "Please check if the imageurl is correct.\nerror_message: %s" % (e)}
    image_info = (fsprotocol.upper(),port(fsport),dir(fsdir),fsip,image,fsusername,fspassword)
    return {'ret': True, 'msg':"Analysis successful", 'image_info': image_info}

def flush(percent):
    list = ['|', '\\', '-', '/']
    for i in list:
        sys.stdout.write(' ' * 100 + '\r')
        sys.stdout.flush()
        sys.stdout.write(i + (('          PercentComplete: %d' %percent) if percent > 0 else '') + '\r')
        sys.stdout.flush()
        time.sleep(0.5)


def task_monitor(REDFISH_OBJ, task_uri):
    """Monitor task status"""
    RUNNING_TASK_STATE = ["New", "Pending", "Service", "Starting", "Stopping", "Running", "Cancelling", "Verifying"]
    END_TASK_STATE = ["Cancelled", "Completed", "Exception", "Killed", "Interrupted", "Suspended"]
    current_state = ""
    messages = []
    percent = 0
    num_503 = 0
    while True:
        response_task_uri = REDFISH_OBJ.get(task_uri, None)
        if response_task_uri.status == 200:
            task_state = response_task_uri.dict["TaskState"]
            if 'Messages' in response_task_uri.dict:
                messages = response_task_uri.dict['Messages']
            if 'PercentComplete' in response_task_uri.dict:
                percent = response_task_uri.dict['PercentComplete']
            if task_state in RUNNING_TASK_STATE:
                if task_state != current_state:
                    current_state = task_state
                    print('Task state is %s, wait a minute' % current_state)
                    continue
                else:
                    flush(percent)
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
                sys.stdout.write(' ' * 100 + '\r')
                sys.stdout.flush()
                print("End of the task")
                result = {'ret':True, 'task_state':task_state, 'msg': ' Messages: %s' %str(messages) if messages != [] else ''}
                return result
            else:
                result = {'ret':False, 'task_state':task_state}
                result['msg'] = ('Unknown TaskState %s. ' %task_state) + 'Task Not conforming to Schema Specification. ' + (
                    'Messages: %s' %str(messages) if messages != [] else '')
                return result
        else:
            if response_task_uri.status == 503 and num_503 < 3:
                num_503 += 1
                continue
            else:
                message = utils.get_extended_error(response_task_uri)
                result = {'ret': False, 'task_state':None, 'msg': "Url '%s' response Error code %s, \nError message :%s" % (
                    task_uri, response_task_uri.status, message)}
                return result


import argparse
def add_helpmessage(argget):
    argget.add_argument('--image', type=str, help='Specify the firmware to be updated.')
    argget.add_argument('--targets', nargs='*', help='Input the targets list, use space to seperate them.')
    argget.add_argument('--fsprotocol', type=str, choices=["SFTP", "TFTP", "HTTPPUSH", "HTTP", "HTTPS"], help='Specify the file server protocol.Support:["SFTP", "TFTP", "HTTPPUSH", "HTTP", "HTTPS"]. HTTPPUSH update supports file upload from local that uses binary data posting.')
    argget.add_argument('--fsip', type=str, help='Specify the file server ip.')
    argget.add_argument('--fsport', type=str, default='', help='Specify the file server port')
    argget.add_argument('--fsusername', type=str, help='Specify the file server username, only for SFTP')
    argget.add_argument('--fspassword', type=str, help='Specify the file server password, only for SFTP')
    argget.add_argument('--fsdir', type=str, help='Specify the file server dir to the firmware upload.')
    argget.add_argument('--applytime', type=str, default='Immediate', choices=["Immediate", "OnReset", "OnStartUpdateRequest"], help='Specifiy when to start to update SimpleUpdate-provided firmware.Accepted settings are ["Immediate", "OnReset", "OnStartUpdateRequest"]')
    argget.add_argument('--imageurl', type=str, help="Specify the firmware link to be updated.")

import os
import configparser
def add_parameter():
    """Add update firmware parameter"""
    argget = utils.create_common_parameter_list(example_string='''
    Example of HTTPS:
      "python update_firmware.py -i 10.10.10.10 -u USERID -p PASSW0RD --imageurl https://10.10.10.11:80/fspath/lnvgy_fw_raid_mr3.5.940-j9337-00b2_anyos_comp.zip"
      "python update_firmware.py -i 10.10.10.10 -u USERID -p PASSW0RD --fsprotocol HTTPS --fsip 10.10.10.11 --fsport 80 --fsdir /fspath/ --image lnvgy_fw_raid_mr3.5.940-j9337-00b2_anyos_comp.zip"
    Example of SFTP:
      "python update_firmware.py -i 10.10.10.10 -u USERID -p PASSW0RD --targets https://10.10.10.10/redfish/v1/UpdateService/FirmwareInventory/Slot_7.Bundle  --imageurl sftp://mysftpuser:mysftppassword@10.10.10.11/fspath/lnvgy_fw_sraidmr35_530-50.7.0-2054_linux_x86-64.bin"
      "python update_firmware.py -i 10.10.10.10 -u USERID -p PASSW0RD --targets https://10.10.10.10/redfish/v1/UpdateService/FirmwareInventory/Slot_7.Bundle --fsprotocol SFTP --fsip 10.10.10.11 --fsusername mysftpuser --fspassword mysftppassword --fsdir /fspath/ --image lnvgy_fw_sraidmr35_530-50.7.0-2054_linux_x86-64.bin"
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
    parameter_info['applytime'] = args.applytime
    parameter_info['imageurl'] = args.imageurl

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
        applytime = parameter_info['applytime']
        imageurl = parameter_info['imageurl']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Update firmware result and check result
    result = update_firmware(ip, login_account, login_password, image, targets, fsprotocol, fsip, fsport, fsusername, fspassword, fsdir, imageurl, applytime)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)

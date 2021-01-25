###
#
# Lenovo Redfish examples - Lenovo Update Firmware
#
# Copyright Notice:
#
# Copyright 2020 Lenovo Corporation
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

# This script is designed to support firmware update via lenovo OEM redfish APIs, especially for SR635/SR655 products.
# For other products, please use update_firmware.py directly.

import sys
import redfish
import json
import update_firmware
import lenovo_utils as utils
import requests
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.auth import HTTPBasicAuth

def lenovo_update_firmware(ip, login_account, login_password, image, targets, fsprotocol, fsip, fsport, fsusername, fspassword, fsdir):
    """ Lenovo update firmware
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
    result = {}
    download_flag = False
    fixid = os.path.splitext(image)[0]
    xml_file = fixid + '.xml'
    # Connect using the address, account name, and password
    login_host = "https://" + ip
    try:
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        REDFISH_OBJ.login(auth="basic")
    except Exception as e:
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct" % repr(e)}
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

        if fsprotocol.lower() != 'http':
            # Check user specify parameter
            if fsprotocol.upper() in ["SFTP", "TFTP"]:
                download_flag = sftp_download_xmlfile(xml_file, fsip, fsport, fsusername, fspassword, fsdir)
                if fsprotocol.upper() == 'TFTP':
                    fsport = '69'
                    fsdir = '/upload'

            # Defines a dictionary for storing pre request information.
            if not download_flag:
                xml_file_path = fsdir + os.sep + fixid + '.xml'
            else:
                xml_file_path = os.getcwd() + os.sep + xml_file

            if os.path.isfile(xml_file_path):
                sups_info_dict = parse_xml(xml_file_path)
                if download_flag:
                    # Delete xml file
                    os.remove(xml_file_path)
            else:
                result = {'ret': False, 'msg': "The firmware xml doesn't exist, please download the firmware xml file."}
                return result

            # Check whether the prerequest version meets the requirements
            prereq_list = sups_info_dict['prereq']
            if prereq_list:
                pre_result = check_pre_req_version(prereq_list,response_update_service_url,REDFISH_OBJ)
                if pre_result['ret'] != True:
                    result = pre_result
                    return result

        if response_update_service_url.status == 200:
            # Check if BMC is 20A or before version of SR635/655. if yes, go through OEM way, else, call standard update way.
            if "Oem" in response_update_service_url.dict['Actions']:
                # Check whether the firmware is BMC or UEFI
                if targets[0].upper() not in ["BMC", "UEFI"]:
                    result = {'ret': False,
                              'msg': "SR635/SR655 products only supports specifying BMC or UEFI to refresh."}
                    return result

                # Check if multiparthttppushuri exists between response_update_service_url.dict['Oem']['AMIUpdateService'] / response_update_service_url.dict
                multiparthttppushuri_exist = False
                multiparthttppushuri_oem_exist = False
                if 'Oem' in response_update_service_url.dict:
                    if 'AMIUpdateService' in response_update_service_url.dict['Oem']:
                        if "MultipartHttpPushUri" in response_update_service_url.dict['Oem']['AMIUpdateService']:
                            multiparthttppushuri_oem_exist = True
                if "MultipartHttpPushUri" in response_update_service_url.dict:
                    multiparthttppushuri_exist = True
                # if yes, use multipart Uri to update Firmware
                if (multiparthttppushuri_oem_exist is True or multiparthttppushuri_exist is True) and fsprotocol.upper() == "HTTPPUSH":
                    if multiparthttppushuri_oem_exist is True:
                        firmware_update_url = login_host + response_update_service_url.dict['Oem']['AMIUpdateService']["MultipartHttpPushUri"]
                    elif multiparthttppushuri_exist is True:
                        firmware_update_url = login_host + response_update_service_url.dict["MultipartHttpPushUri"]
                    BMC_Parameter = {"Targets": ["/redfish/v1/Managers/Self"]}
                    if targets[0].upper() == "BMC":
                        Oem_Parameter = {"FlashType": "HPMFwUpdate", "UploadSelector": "Default"}
                    elif targets[0].upper() == "UEFI":
                        Oem_Parameter = {"FlashType": "UEFIUpdate", "UploadSelector": "Default"}
                    else:
                        result = {'ret': False,
                                  'msg': "SR635/SR655 products only supports specifying BMC or UEFI to refresh."}
                        return result

                    F_image = open(fsdir + os.sep + image, 'rb')
                    # Specify the parameters required to update the firmware
                    files = {'UpdateParameters': ("parameters.json", json.dumps(BMC_Parameter), 'application/json'),
                             'OemParameters': ("oem_parameters.json", json.dumps(Oem_Parameter), 'application/json'),
                             'UpdateFile': (image, F_image, 'multipart/form-data')}

                    # Send a post command through requests to update the firmware
                    # Ignore SSL Certificates
                    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                    # Set BMC access credential
                    auth = HTTPBasicAuth(login_account, login_password)
                    print("Start to upload the image, may take about 3~10 minutes...\n")
                    response = requests.post(firmware_update_url, auth=auth, files=files, verify=False)
                    response_code = response.status_code
                    F_image.close()
                else:
                    if fsprotocol.upper() != "HTTP":
                        result = {'ret': False, 'msg': "SR635/SR655 products only supports the HTTP protocol to update firmware."}
                        return result
                    # for SR635/SR655 products, refresh the firmware with OEM action
                    Oem_dict = response_update_service_url.dict['Actions']['Oem']
                    if "#UpdateService.HPMUpdate" in Oem_dict and targets[0].upper() == "BMC":
                        firmware_update_url = response_update_service_url.dict['Actions']['Oem']['#UpdateService.HPMUpdate']['target']
                    elif "#UpdateService.UEFIUpdate" in Oem_dict and targets[0].upper() == "UEFI":
                        firmware_update_url = response_update_service_url.dict['Actions']['Oem']["#UpdateService.UEFIUpdate"]['target']
                    else:
                        result = {'ret': False,
                                  'msg': "Check whether the BMC is 20A version of SR635/655"}
                        return result
                    port = (lambda fsport: ":" + fsport if fsport else fsport)
                    dir = (lambda fsdir: "/" + fsdir.strip("/") if fsdir else fsdir)
                    Image_uri = fsprotocol.lower() + "://" + fsip + port(fsport) + dir(fsdir) + "/" + image
                    body = {}
                    body["ImageURI"] = Image_uri
                    body["TransferProtocol"] = fsprotocol.upper()
                    response = REDFISH_OBJ.post(firmware_update_url, body=body)
                    response_code = response.status
            else:
                result = update_firmware.update_firmware(ip, login_account, login_password, image, targets, fsprotocol, fsip,
                                                   fsport, fsusername, fspassword, fsdir)
                return result

            if response_code in [200, 202, 204]:
                # For BMC update, BMC will restart automatically, the session connection will be disconnected, user have to wait BMC to restart.
                # For UEFI update, the script can monitor the update task via BMC.
                if targets[0].upper() == "BMC":
                    result = {'ret': True, 'msg': 'BMC refresh successfully, wait about 5 minutes for BMC to restart.'}
                    return result
                else:
                    if fsprotocol.upper() == "HTTP":
                        task_uri = update_service_url
                    else:
                        task_uri = response.headers['Location']
                    result = task_monitor(REDFISH_OBJ, task_uri)

                    if result["ret"] is True:
                        task_state = result["task_state"]
                        if task_state in ["Completed", "Done"]:
                            result = {'ret': True, 'msg': "Update firmware successfully"}
                        else:
                            task_id = result["id"]
                            result = {'ret': False,'msg': "Failed to update firmware, task id is %s, task state is %s" % (task_id, task_state)}
                        # Delete task
                        REDFISH_OBJ.delete(task_uri, None)
                        return result
                    else:
                        return result
            else:
                error_message = utils.get_extended_error(response)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s, \nError message: %s" % (
                    firmware_update_url, response_code, error_message)}
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


import xml.etree.ElementTree as ET
import os
import re
def parse_xml(xml_file_path):
    """Parse fixid xml files"""
    tree = ET.parse(xml_file_path)
    root = tree.getroot()
    # Build an empty dictionary to store information in XML
    sups_dict = {}
    # Build an empty list to store prerequest information
    pre_req = []
    mt_list = []
    # Add MT
    info_list = ["category", "Version", "payload", "xmlFilename", "preReq", "buildNumber"]
    for node in root.iter('PROPERTY.ARRAY'):
        if "preReq" in node.attrib['NAME']:
            for value in node.iter('VALUE'):
                pre_req.append(value.text)
        if "applicableMachineTypes" in node.attrib['NAME']:
            for MT in node.iter('VALUE'):
                regularity = re.compile(r"[[](.*?)[]]")
                mt = regularity.findall(MT.text)
                mt_list.append(mt)
    sups_dict['prereq'] = pre_req
    for node in root.iter('PROPERTY'):
        for info_name in info_list:
            if node.attrib['NAME'] == info_name:
                for value in node.iter('VALUE'):
                    sups_dict[info_name] = value.text
    sups_dict['Version'] = sups_dict['Version'].split(' ')[1]
    sups_dict['mt_list'] = mt_list
    return sups_dict


def check_pre_req_version(prereq_list,response_update_service_url,REDFISH_OBJ):
    ''' Check whether the prerequest version meets the requirements '''
    pre_req_flag_xcc = {'status': True}
    pre_req_flag_uefi = {'status': True}
    firmwareInventory_url_bmc = response_update_service_url.dict['FirmwareInventory']['@odata.id'] + '/' + 'BMC-Primary'
    update_firmware_dict_bmc = REDFISH_OBJ.get(firmwareInventory_url_bmc, None)
    firmwareInventory_url_uefi = response_update_service_url.dict['FirmwareInventory']['@odata.id'] + '/' + 'UEFI'
    update_firmware_dict_uefi = REDFISH_OBJ.get(firmwareInventory_url_uefi, None)
    for pre_req in prereq_list:
        # 'lnvgy_fw_xcc_afbt05m-0.02_anyos_noarch'
        pre_req_list = pre_req.split('_')
        if pre_req_list[2].lower() in ['xcc', 'bmc', 'uefi', 'lxpm', 'drvwn', 'drvln']:
            pre_software = pre_req_list[3].split('-')[0][:3].lower()
            pre_version = pre_req_list[3].split('-')[1]
            if pre_req_list[2].lower() in ['xcc', 'bmc']:
                # Check the versions on different machines,for example SR650 and SR635
                if 'BMC' in update_firmware_dict_bmc.dict['SoftwareId']:
                    current_software = update_firmware_dict_bmc.dict['SoftwareId'].split('-')[1][:3].lower()
                    current_version = update_firmware_dict_bmc.dict['Version'].split('-')[1]
                else:
                    current_software = update_firmware_dict_bmc.dict['SoftwareId'][:3].lower()
                    current_version = update_firmware_dict_bmc.dict['Version']
                if current_software == pre_software:
                    if current_version >= pre_version:
                        pre_req_flag_xcc['status'] = True
                    else:
                        pre_req_flag_xcc['status'] = False
                        pre_req_flag_xcc['type'] = 'BMC-Priamry'
                        pre_req_flag_xcc['current_version'] = current_version
                        pre_req_flag_xcc['pre_req_version'] = pre_version
                else:
                    continue
            elif pre_req_list[2].lower() == 'uefi':
                if 'UEFI' in update_firmware_dict_uefi.dict['SoftwareId']:
                    current_version = update_firmware_dict_uefi.dict['Version'].split('-')[1]
                else:
                    current_version = update_firmware_dict_uefi.dict['Version']
                if current_version > pre_version:
                    pre_req_flag_uefi['status'] = True
                else:
                    pre_req_flag_uefi['status'] = False
                    pre_req_flag_uefi['type'] = 'UEFI'
                    pre_req_flag_uefi['current_version'] = current_version
                    pre_req_flag_uefi['pre_req_version'] = pre_version
            else:
                pre_req_flag_xcc['status'] = False

    if pre_req_flag_xcc['status'] == False or pre_req_flag_uefi['status'] == False:
        if pre_req_flag_xcc['status'] != pre_req_flag_uefi['status']:
            if pre_req_flag_xcc['status'] == False:
                pre_req_flag = pre_req_flag_xcc
            else:
                pre_req_flag = pre_req_flag_uefi
            result = {'ret': False,
                      'msg': "Update firmware was not performed. "
                             "Because the current version %s of %s does not meet the pre request of version %s. " %
                             (pre_req_flag['current_version'], pre_req_flag['type'], pre_req_flag['pre_req_version'])
                      }
            return result
        else:
            result = {'ret': False,
                      'msg': "Update firmware was not performed. "
                             "Because the current version %s of %s does not meet the pre request of version %s and the current version %s of %s does not meet the pre request of version %s. " %
                             (pre_req_flag_xcc['current_version'], pre_req_flag_xcc['type'],
                              pre_req_flag_xcc['pre_req_version'],
                              pre_req_flag_uefi['current_version'], pre_req_flag_uefi['type'],
                              pre_req_flag_uefi['pre_req_version'])
                      }
            return result
    else:
        result = {'ret': True}
        return result


import paramiko
def sftp_download_xmlfile(xml_file, fsip, fsport, fsusername, fspassword, fsdir):
    """Download the firmware xml file"""
    # Connect file server using the fsip, fsusername, and fspassword
    download_flag = False
    try:
        sf = paramiko.Transport((fsip, int(fsport)))
        sf.connect(username=fsusername, password=fspassword)
        sftp = paramiko.SFTPClient.from_transport(sf)
        # Judge whether the file is on SFTP.
        files_list = sftp.listdir(fsdir)
        remote_path = "/" + fsdir + "/"+ xml_file
        local_path = os.getcwd() + os.sep + xml_file

        if xml_file in files_list:
            sftp.get(remote_path,local_path)
            download_flag = True
        else:
            print("There is no firmware xml file on the remote server, please download the firmware xml file..")
        sf.close()
    except Exception as e:
        print('download exception:', e)
    return download_flag


def task_monitor(REDFISH_OBJ, task_uri):
    """Monitor task status"""
    END_TASK_STATE = ["Cancelled", "Completed", "Exception", "Killed", "Interrupted", "Suspended", "Done", "Failed when Flashing Image."]
    time_start=time.time()
    print("Start to refresh the firmware, please wait about 3~10 minutes...")
    while True:
        response_task_uri = REDFISH_OBJ.get(task_uri, None)
        if response_task_uri.status in [200, 202]:
            if "TaskState" in response_task_uri.dict:
                task_state = response_task_uri.dict["TaskState"]
            elif "Oem" in response_task_uri.dict:
                if "UpdateStatus" in response_task_uri.dict['Oem']:
                    task_state = response_task_uri.dict["Oem"]["UpdateStatus"]
                else:
                    task_state = "Exception"
            else:
                task_state = "Exception"
            # Monitor task status until the task terminates
            if task_state in END_TASK_STATE:
                result = {'ret':True, 'task_state': task_state, 'id': response_task_uri.dict['Id']}
                return result
            else:
                time_now = time.time()
                # wait for max 10 minutes to avoid endless loop.
                if time_now - time_start > 600:
                    result = {'ret': False, 'task_state': task_state, 'msg':  "It took too long time to update the firmware, over 10 minutes. Task id is %s ." % response_task_uri.dict['Id']}
                    return result
                time.sleep(10)
        else:
            message = utils.get_extended_error(response_task_uri)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s, \nError message :%s" % (task_uri, response_task_uri.status, message)}
            return result


import argparse
def add_helpmessage(argget):
    argget.add_argument('--image', type=str, required=True, help='Specify the fixid of the firmware to be updated.')
    argget.add_argument('--targets', nargs='*', help='For SR635/SR655 products, only support BMC or UEFI, for other products, specify the targets of firmware to refresh. '
                                                     'Only support the target of BMC-Backup for 20A and after version of XCC.')
    argget.add_argument('--fsprotocol', type=str, choices=["SFTP", "TFTP", "HTTP", "HTTPPUSH"], help='Specify the file server protocol. Support:["SFTP", "TFTP", "HTTPPUSH", "HTTP"]')
    argget.add_argument('--fsip', type=str, help='Specify the file server ip.')
    argget.add_argument('--fsport', type=str, default='', help='Specify the file server port')
    argget.add_argument('--fsusername', type=str, help='Specify the file server username.')
    argget.add_argument('--fspassword', type=str, help='Specify the file server password.')
    argget.add_argument('--fsdir', type=str, help='Specify the path to the firmware, either on the file server or locally.')


import os
import configparser
def add_parameter():
    """Add update firmware parameter"""
    argget = utils.create_common_parameter_list(example_string='''
    Example of SFTP:
      "python lenovo_update_firmware.py -i 10.10.10.10 -u USERID -p PASSW0RD --targets https://10.10.10.10/redfish/v1/UpdateService/FirmwareInventory/Slot_7.Bundle --fsprotocol SFTP --fsip 10.10.10.11 --fsusername mysftp --fspassword mypass --fsdir /fspath/ --image lnvgy_fw_sraidmr35_530-50.7.0-2054_linux_x86-64.bin"
    Example of TFTP:
      "python lenovo_update_firmware.py -i 10.10.10.10 -u USERID -p PASSW0RD --targets https://10.10.10.10/redfish/v1/UpdateService/FirmwareInventory/Slot_7.Bundle --fsprotocol TFTP --fsip 10.10.10.11 --fsdir /fspath/ --image lnvgy_fw_sraidmr35_530-50.7.0-2054_linux_x86-64.bin"
    Example of HTTPPUSH:
      "python lenovo_update_firmware.py -i 10.10.10.10 -u USERID -p PASSW0RD --fsprotocol HTTPPUSH --fsdir /fspath/ --image lnvgy_fw_sraidmr35_530-50.7.0-2054_linux_x86-64.bin"
    Example of HTTP:
      "python lenovo_update_firmware.py -i 10.10.10.10 -u USERID -p PASSW0RD --targets BMC --fsprotocol HTTP --fsdir /fspath/ --image lnvgy_fw_sraidmr35_530-50.7.0-2054_linux_x86-64.bin"
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
    result = lenovo_update_firmware(ip, login_account, login_password, image, targets, fsprotocol, fsip, fsport, fsusername, fspassword, fsdir)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

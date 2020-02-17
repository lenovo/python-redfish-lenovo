###
#
# Lenovo Redfish examples - Export ffdc data file
#
# Copyright Notice:
#
# Copyright 2018 Lenovo Corporation
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
import redfish
import json
import lenovo_utils as utils
import time
import os


def export_ffdc_data(ip, login_account, login_password, fsprotocol, fsip, fsusername, fspassword, fsdir):
    """Export ffdc data    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params fsip: Specify the file server ip
    :type fsip: string
    :params fsusername: Specify the file server username
    :type fsusername: string
    :params fspassword: Specify the file server password
    :type fspassword: string
    :params fsdir: Specify the file server dir to the firmware upload
    :type fsdir: string
    :returns: returns export ffdc data result when succeeded or error message when failed
    """

    # Connect using the address, account name, and password
    login_host = "https://" + ip 
    try:
        result = {}        
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1')
        REDFISH_OBJ.login(auth="session")
    except Exception as e:
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct" % repr(e)}
        return result

    try:
        # Get ServiceRoot resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1/Managers', None)
        # Get managers collection
        if response_base_url.status == 200:
            managers_list = response_base_url.dict['Members']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '/redfish/v1/Managers' response Error code %s \nerror_message: %s" % (response_base_url.status, error_message)}
            return result

        # Get manager uri form managers collection
        for i in managers_list:
            manager_uri = i["@odata.id"]
            response_manager_uri =  REDFISH_OBJ.get(manager_uri, None)
            if response_manager_uri.status == 200:
                # Get servicedata uri via manager uri response resource
                servicedata_uri = response_manager_uri.dict['Oem']['Lenovo']['ServiceData']['@odata.id']
            else:
                error_message = utils.get_extended_error(response_manager_uri)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (manager_uri, response_manager_uri.status, error_message)}
                return result

            # Get servicedata resource
            response_servicedata_uri = REDFISH_OBJ.get(servicedata_uri, None)
            if response_servicedata_uri.status == 200:
                # Get export ffdc data uri via servicedaata uri response resource
                ffdc_data_uri = response_servicedata_uri.dict['Actions']['#LenovoServiceData.ExportFFDCData']['target']

                # Build post request body and Get the user specified parameter
                body = {}
                body['InitializationNeeded'] = True
                body['DataCollectionType'] = "ProcessorDump"

                # Check the transport protocol, only support sftp and tftp protocols
                export_uri = ""
                if fsprotocol:
                    export_uri = fsprotocol.lower() + "://" + fsip + ":/" + fsdir + "/"
                    body['ExportURI'] = export_uri
                    if fsprotocol.lower() not in ["sftp", "tftp"]:
                        error_message = "Please check the parameter ExportURI, the format of ExportURI must be 'sftp://...' or 'tftp://...'"
                        result = {"ret": False, "msg":error_message}
                        return result


                    # Get the user specified sftp username and password when the protocol is sftp
                    if fsprotocol.upper() == "SFTP":
                        if not fsusername or not fspassword:
                            error_message = "When the protocol is sftp, you must specify the sftp username and password"
                            result = {"ret": False, "msg": error_message}
                            return result
                        else:
                            body['Username'] = fsusername
                            body['Password'] = fspassword
                time_start=time.time()
                response_ffdc_data_uri = REDFISH_OBJ.post(ffdc_data_uri, body=body)
                print("Start downloading ffdc files and may need to wait a few minutes...")
                # The system will create a task to let user know the transfer progress and return a download URI
                if response_ffdc_data_uri.status == 202:
                    task_uri = response_ffdc_data_uri.dict['@odata.id']
                    # Continue to get the task response until the task is completed
                    while True:
                        response_task_uri = REDFISH_OBJ.get(task_uri, None)
                        if response_task_uri.status == 200:
                            task_state = response_task_uri.dict['TaskState']
                            if task_state == "Completed":
                                # If the user does not specify export uri, the ffdc data file will be downloaded to the local
                                if not fsprotocol and 'Oem' in response_task_uri.dict:
                                    download_uri = response_task_uri.dict['Oem']['Lenovo']['FFDCForDownloading']['Path']
                                    # Download FFDC data from download uri when the task completed
                                    download_sign = download_ffdc(ip, login_account, login_password, download_uri)
                                    if download_sign:
                                        ffdc_file_name = os.getcwd() + os.sep + download_uri.split('/')[-1]
                                        time_end = time.time()    
                                        print('time cost: %.2f' %(time_end-time_start)+'s')
                                        result = {'ret': True, 'msg':  "The FFDC data is saved as %s " %(ffdc_file_name)}
                                    else:
                                        result = {'ret': False, 'msg':  "The FFDC data download failed"}
                                    break
                                elif fsprotocol:
                                    time_end = time.time()    
                                    print('time cost: %.2f' %(time_end-time_start)+'s')
                                    result = {'ret': True, 'msg':  "The FFDC data is saved as %s " %export_uri}
                                    break
                                else:
                                    result = {'ret': False, 'msg':  "If the user wants to download to a remote server, you need to specify the server type."}
                                    break
                            elif task_state in ["Exception", "Killed"]:
                                result = {"ret": False, "msg": "Task state is %s, The FFDC data download failed" %task_state}
                                break
                            else:
                                flush()
                        else:
                            error_message = utils.get_extended_error(response_task_uri)
                            result = {'ret': False, 'msg': "Url '%s' response task uri Error code %s \nerror_message: %s" % (task_uri, response_task_uri.status, error_message)}
                            break

                    # Delete the task when the task state is completed
                    REDFISH_OBJ.delete(task_uri, None)
                else:
                    error_message = utils.get_extended_error(response_ffdc_data_uri)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (ffdc_data_uri, response_ffdc_data_uri.status, error_message)}
                    return result
            else:
                error_message = utils.get_extended_error(response_servicedata_uri)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (servicedata_uri, response_servicedata_uri.status, error_message)}
                return result
    except Exception as e:
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
    finally:
        REDFISH_OBJ.logout() 
        return result


def flush():
    list = ['|', '\\', '-', '/']
    for i in list:
        sys.stdout.write(' ' * 100 + '\r')
        sys.stdout.flush()
        sys.stdout.write(i + '\r')
        sys.stdout.flush()
        time.sleep(0.1)


# download FFDC file
import requests
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning


def download_ffdc(ip, login_account, login_password, download_uri):
    """Download ffdc file from download_uri"""
    # closed ssl security warning 
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    temp = False
    try:
        download_sign = False
        ip = ip
        username = login_account
        password = login_password
        download_uri = "https://" + ip + download_uri
        # Get session Id
        session_uri = "https://" + ip + "/redfish/v1/SessionService/Sessions/"
        body = {"UserName":username, "Password":password}
        headers = {"Content-Type": "application/json"}
        response_session_uri = requests.post(session_uri, data=json.dumps(body), headers = headers, verify=False)
        if response_session_uri.status_code == 201:
            x_auth_token = response_session_uri.headers['X-Auth-Token']
            location_uri = response_session_uri.headers['Location']
        else:
            print("error_code:%s" %response_session_uri.status_code)
            return

        jsonHeader = {"X-Auth-Token":x_auth_token, "Content-Type":"application/json"}
        # Download FFDC file
        response_download_uri = requests.get(download_uri, headers=jsonHeader, verify=False)
        if response_download_uri.status_code == 200:
            ffdc_file_name = download_uri.split('/')[-1]
            get_cwd = os.getcwd()
            with open(os.getcwd() + os.sep + ffdc_file_name, 'wb') as f:
                f.write(response_download_uri.content)
                download_sign = True
        else:
            print("response manaegr uri Error code %s" %response_download_uri.status_code)
    except Exception as e:
        print(e)
    finally:
        # Delete session
        delete_session_uri = "https://" + ip + location_uri
        jsonHeader = {"X-Auth-Token":x_auth_token, "Content-Type":"application/json"}
        response_delete_session = requests.delete(delete_session_uri, headers=jsonHeader, verify=False)
        if response_delete_session.status_code == 204 and download_sign:
            temp = True
        return temp


import argparse
def add_helpmessage(argget):
    argget.add_argument('--fsprotocol', type=str, help='Specify the file server protocol. Support:["SFTP", "TFTP"]')
    argget.add_argument('--fsip', type=str, help='Specify the file server ip.')
    argget.add_argument('--fsusername', type=str, help='Specify the file server username.')
    argget.add_argument('--fspassword', type=str, help='Specify the file server password.')
    argget.add_argument('--fsdir', type=str, help='Specify the directory under which ffdc data will be saved on file server.')


import configparser
def add_parameter():
    """Add get servicedata parameter"""
    argget = utils.create_common_parameter_list()
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
        config_ini_info["fsusername"] = cfg.get('FileServerCfg', 'FSusername')
        config_ini_info["fspassword"] = cfg.get('FileServerCfg', 'FSpassword')
        config_ini_info["fsdir"] = cfg.get('FileServerCfg', 'FSdir')

    # Get the user specify parameter from the command line
    parameter_info = utils.parse_parameter(args)
    parameter_info['fsprotocol'] = args.fsprotocol
    parameter_info['fsip'] = args.fsip
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

    # Get file data info from the parameters user specified
    fsprotocol = parameter_info['fsprotocol']
    fsip = parameter_info['fsip']
    fsusername = parameter_info['fsusername']
    fspassword = parameter_info['fspassword']
    fsdir = parameter_info['fsdir']

    # export ffdc result and check result
    result = export_ffdc_data(ip, login_account, login_password, fsprotocol, fsip, fsusername, fspassword, fsdir)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

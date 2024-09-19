###
#
# Lenovo Redfish examples - BMC configuration restore
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
import traceback
import lenovo_utils as utils
import os
import time


# get file size
def getDocSize(path):
    try:
        size = os.path.getsize(path)
        return size/1024
    except Exception as err:
        result = {'ret': False, 'msg': "Failed to get file size %s. " % path + str(err)}
        return result


def check_whether_new_schema(odatatype, REDFISH_OBJ):
    boolret = False
    found = False

    #get schema prefix from @odata.type
    schema_prefix = ""
    temp = odatatype.split('#')[-1]
    if len(temp.split('.')) >2:
        schema_prefix = temp.split('.')[0] + '.' + temp.split('.')[1]
    else:
        schema_prefix = temp.split('.')[0]

    #search schema prefix in JsonSchemas collection, check whether keyword ConfigContent in found schema json file
    response_base_url = REDFISH_OBJ.get("/redfish/v1", None)
    if response_base_url.status == 200:
        Json_Schemas = response_base_url.dict['JsonSchemas']['@odata.id']
        response_json_schemas = REDFISH_OBJ.get(Json_Schemas, None)
        if response_json_schemas.status == 200:
            schema_list = response_json_schemas.dict['Members']
            for schema in schema_list:
                if found:
                    break
                if schema_prefix not in schema["@odata.id"]:
                    continue
                found = True
                schema_url = schema["@odata.id"]
                response = REDFISH_OBJ.get(schema_url, None)
                for location in response.dict["Location"]:
                    if "en" not in location["Language"]:
                        continue
                    uri = location["Uri"]
                    response_uri = REDFISH_OBJ.get(uri, None)
                    if response_uri.status == 200 and 'ConfigContent' in str(response_uri.dict):
                        boolret = True
                        return boolret

    return boolret


def lenovo_bmc_config_restore(ip, login_account, login_password, backup_password, backup_file, httpip, httpport, httpdir):
    """BMC configuration restore
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params backup_password: backup password by user specified
        :type backup_password: string
        :params backup_file: backup file by user specified
        :type backup_file: string
        :params httpip: Specify the HTTP file server ip
        :type httpip: string
        :params httpport: Specify the HTTP file server port
        :type httpport: int
        :params httpdir: Specify the file server dir
        :type httpdir: string
        :returns: returns get bmc configuration result when succeeded or error message when failed
        """

    result = {}
    # check passwd len
    if len(backup_password) < 9:
        result = {'ret': False, 'msg': "Password at least 9 characters needed"}
        return result

    if (httpip is None or httpip == '') and backup_file:
        try:
            back_file = open(backup_file, 'r')
        except:
            result = {'ret': False, 'msg': "Failed to open file %s,Please check your backup file path" % backup_file}
            return result
        #check backup file size
        size = getDocSize(backup_file)
        if not isinstance(size, dict):
            if(size > 255):
                result = {'ret': False,
                        'msg': "Failed to restore the configuration because the size of configuration data is over 255KB."}
                return result
        else:
            return size


    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    try:
        # Get ServiceBase resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        # Get response_base_url
        if response_base_url.status == 200:
            manager_url = response_base_url.dict['Managers']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result
    
        # Get ServiceBase resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        # Get response_base_url
        if response_base_url.status == 200:
            manager_url = response_base_url.dict['Managers']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result
    
        # Get /redfish/v1/Managers resource
        response_manager_url = REDFISH_OBJ.get(manager_url, None)
        bmc_time_detail = []
        if response_manager_url.status != 200:
            error_message = utils.get_extended_error(response_manager_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                manager_url, response_manager_url.status, error_message)}
            return result
    
        for request in response_manager_url.dict['Members']:
            # Get Manager member resource
            request_url = request['@odata.id']
            response_url = REDFISH_OBJ.get(request_url, None)
            if response_url.status != 200:
                error_message = utils.get_extended_error(response_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    request_url, response_url.status, error_message)}
                return result
            # Check whether action is supported or not
            if 'Oem/Lenovo/Configuration' not in str(response_url.dict) and '#Manager.Restore' not in str(response_url.dict):
                result = {'ret': False, 'msg': "Not support bmc configuration restore."}
                return result

            # Restore via action Oem/Lenovo/Configuration
            if 'Oem/Lenovo/Configuration' in str(response_url.dict):
                if (httpip is not None and httpip != '') or (httpdir is not None and httpdir != ''):
                    error_message = "Target Server do not support bmc config backup/restore via HTTP file server, please use local config file to restore."
                    result = {"ret": False, "msg": error_message}
                    return result
                # Get configuration url
                oem_resource = response_url.dict['Oem']['Lenovo']
                config_url = oem_resource['Configuration']['@odata.id']
                response_config_url = REDFISH_OBJ.get(config_url, None)
                if response_config_url.status != 200:
                    error_message = utils.get_extended_error(response_config_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        config_url, response_config_url.status, error_message)}
                    return result
        
                #restore configuration
                restore_target_url = response_config_url.dict['Actions']['#LenovoConfigurationService.RestoreConfiguration']['target']
                try:
                    list_data = json.load(back_file)
                except:
                    list_data = back_file.read()
                if len(list_data) == 0:
                    result = {'ret': False,
                              'msg': "list_data is empty"}
                    return result

                # GET model
                system = utils.get_system_url("/redfish/v1", "None", REDFISH_OBJ)
                if not system:
                    result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
                    REDFISH_OBJ.logout()
                    return result

                for i in range(len(system)):
                    system_url = system[i]
                    response_system_url = REDFISH_OBJ.get(system_url, None)
                    if response_system_url.status != 200:
                        error_message = utils.get_extended_error(response_system_url)
                        result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                            system_url, response_system_url.status, error_message)}
                        REDFISH_OBJ.logout()
                        return result
                    model = response_system_url.dict["Model"]

                restore_body = {}
                if "V4" in model.upper():
                    EncryptData = ""
                    VerificationCode = ""
                    for item in list_data:  
                        if isinstance(item, dict):  
                            if "EncryptData" in item:
                                EncryptData = item["EncryptData"]
                            if "VerificationCode" in item:
                                VerificationCode = item["VerificationCode"]
                    if EncryptData and VerificationCode:
                        restore_body = {
                            "EncryptData":EncryptData,
                            "Passphrase":backup_password,
                            "VerificationCode": VerificationCode
                        }
                    else:
                        result = {'ret': False, 'msg': "The specified backupfile is error, you can get it by executing lenovo_bmc_config_backup.py." }
                        return result
                else:
                    #check schema to specify proper body
                    if check_whether_new_schema(response_config_url.dict['@odata.type'], REDFISH_OBJ) == True:
                        restore_body = {
                            "ConfigContent":list_data,
                            "Passphrase":backup_password
                        }
                    else:
                        restore_body = {
                            "bytes":list_data,
                            "Passphrase":backup_password
                        }

                # Perform post to do restore action
                print("It may take 1 or 2 minutes to restore bmc config, please wait...")
                response_restore_url = REDFISH_OBJ.post(restore_target_url, body=restore_body)
                if response_restore_url.status != 200 and response_restore_url.status != 204:
                    error_message = utils.get_extended_error(response_restore_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        restore_target_url, response_restore_url.status, error_message)}
                    return result

                # Check restore status after action
                for i in range(120):
                    response_url = REDFISH_OBJ.get(config_url, None)
                    if response_url.status != 200:
                        error_message = utils.get_extended_error(response_url)
                        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                            request_url, response_url.status, error_message)}
                        return result
                    if 'RestoreStatus' in response_url.dict and 'Restore was successful' in response_url.dict['RestoreStatus']:
                        result = {'ret': True,
                                  'msg':"BMC configuration restore successfully"}
                        return result
                    time.sleep(1)
                    continue

                result = {'ret': True,
                          'msg':"BMC configuration restore does not finished in 2 minutes, please check it manually"}
                return result

            # Restore via action #Manager.Restore for SR635/SR655
            if '#Manager.Restore' in str(response_url.dict):
                if httpip is None or httpip == '' or httpdir is None or httpdir == '':
                    error_message = "Target Server only support HTTP protocol, please use HTTP file server to restore bmc config."
                    result = {"ret": False, "msg": error_message}
                    REDFISH_OBJ.logout()
                    return result
                body = {}
                body['RestoreFileName'] = backup_file
                body['password'] = backup_password
                body['serverIP'] = httpip
                body['serverPort'] = httpport
                body['folderPath'] = httpdir
                export_uri = 'http://' + httpip + ':' + str(httpport) + '/' + httpdir
                
                restore_uri = '/redfish/v1/Managers/Self/Actions/Oem/Lenovo/Restore.start'
                time_start=time.time()
                response_restore_uri = REDFISH_OBJ.post(restore_uri, body=body)
                if response_restore_uri.status != 202:
                    error_message = utils.get_extended_error(response_restore_uri)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (restore_uri, response_restore_uri.status, error_message)}
                    REDFISH_OBJ.logout()
                    return result

                result = {'ret': True,
                          'msg':"BMC will reset to restore configuration, please wait a few minutes for restore action to be finished. (Normally it may need 1~3 minutes.)"}
                return result

    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Exception msg %s" % e}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        if (httpip is None or httpip == '') and backup_file:
            back_file.close()


def add_helpmessage(parser):
    parser.add_argument('--backuppasswd', type=str, required=True, help='The password that you specified when the configuration was exported')
    parser.add_argument('--backupfile', type=str, required=True, help='An file that contains the configuration you wish to restore from local or http file server. Note: SR635/SR655 not support local restore, only support restore from http file server')
    parser.add_argument('--httpip', type=str, help='Specify http file server ip for SR635/SR655.')
    parser.add_argument('--httpport', type=int, default=80, help='Specify http file server port for SR635/SR655, default port is 80.')
    parser.add_argument('--httpdir', type=str, help='Specify the directory on http file server for SR635/SR655.')


import configparser
def add_parameter():
    """Add configuration restore parameter"""
    parameter_info = {}
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
        try:
            config_ini_info["httpip"] = cfg.get('FileServerCfg', 'Httpip')
        except:
            config_ini_info["httpip"] = ''
        try:
            config_ini_info["httpport"] = cfg.get('FileServerCfg', 'Httpport')
        except:
            config_ini_info["httpport"] = ''
        try:
            config_ini_info["httpdir"] = cfg.get('FileServerCfg', 'Httpdir')
        except:
            config_ini_info["httpdir"] = ''

    # Get the user specify parameter from the command line
    parameter_info = utils.parse_parameter(args)
    parameter_info["backuppasswd"] = args.backuppasswd
    parameter_info["backupfile"] = args.backupfile
    parameter_info["httpip"] = args.httpip
    parameter_info["httpport"] = args.httpport
    parameter_info["httpdir"] = args.httpdir

    # The parameters in the configuration file are used when the user does not specify parameters
    for key in parameter_info:
        if not parameter_info[key]:
            if key in config_ini_info:
                parameter_info[key] = config_ini_info[key]
    # Use the port specified in configuration file instead of default 80 port
    if "httpport" in config_ini_info and config_ini_info["httpport"] != '' and args.httpport == 80:
        parameter_info["httpport"] = int(config_ini_info["httpport"])

    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini or command line
    parameter_info = add_parameter()
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    backup_password = parameter_info["backuppasswd"]
    backup_file = parameter_info["backupfile"]
    httpip = parameter_info["httpip"]
    httpport = parameter_info["httpport"]
    httpdir = parameter_info["httpdir"]
    # BMC configuration restore and check result
    result = lenovo_bmc_config_restore(ip, login_account, login_password, backup_password, backup_file, httpip, httpport, httpdir)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
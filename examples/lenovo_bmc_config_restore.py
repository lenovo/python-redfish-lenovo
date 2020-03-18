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
import lenovo_utils as utils
import os

# get file size
def getDocSize(path):
    try:
        size = os.path.getsize(path)
        return size/1024
    except Exception as err:
        sys.stderr.write(err)

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

def lenovo_config_restore(ip, login_account, login_password,backup_password,backup_file):
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
        :returns: returns get bmc configuration result when succeeded or error message when failed
        """

    result = {}
    # check passwd len
    if len(backup_password) < 9:
        result = {'ret': False, 'msg': "Password at least 9 characters needed"}
        return result

    try:
        back_file = open(backup_file, 'r')
    except:
        result = {'ret': False, 'msg': "Failed to open file %s,Please check your backup file path" % backup_file}
        return result
    #check backup file size
    if(getDocSize(backup_file) > 255):
        result = {'ret': False,
                  'msg': "Failed to restore the configuration because the size of configuration data is over 255KB."}
        return result
    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
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
        REDFISH_OBJ.logout()
        back_file.close()
        return result
    response_manager_url = REDFISH_OBJ.get(manager_url, None)
    bmc_time_detail = []
    if response_manager_url.status == 200:
        for request in response_manager_url.dict['Members']:
            request_url = request['@odata.id']
            response_url = REDFISH_OBJ.get(request_url, None)
            if response_url.status == 200:
                # get configuration url
                oem_resource = response_url.dict['Oem']['Lenovo']
                config_url = oem_resource['Configuration']['@odata.id']
                response_config_url = REDFISH_OBJ.get(config_url, None)
                if response_config_url.status == 200:
                    #restore configuration
                    restore_target_url = response_config_url.dict['Actions']['#LenovoConfigurationService.RestoreConfiguration']['target']
                    try:
                        list_data = json.load(back_file)
                    except:
                        result = {'ret': False,
                                  'msg': "load file error,Please check your input file"}
                        REDFISH_OBJ.logout()
                        back_file.close()
                        return result
                    if len(list_data) == 0:
                        result = {'ret': False,
                                  'msg': "list_data is empty"}
                        REDFISH_OBJ.logout()
                        back_file.close()
                        return result

                    #check schema to specify proper body
                    restore_body = {}
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

                    response_restore_url = REDFISH_OBJ.post(restore_target_url, body=restore_body)
                    if response_restore_url.status == 200:
                        result = {'ret': True,
                                  'msg':"BMC configuration restore successfully"}
                        REDFISH_OBJ.logout()
                        back_file.close()
                        return result
                    else:
                        error_message = utils.get_extended_error(response_restore_url)
                        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                            restore_target_url, response_restore_url.status, error_message)}
                        REDFISH_OBJ.logout()
                        back_file.close()
                        return result
                else:
                    error_message = utils.get_extended_error(response_config_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        config_url, response_config_url.status, error_message)}
                    REDFISH_OBJ.logout()
                    back_file.close()
                    return result
            else:
                error_message = utils.get_extended_error(response_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    request_url, response_url.status, error_message)}
                REDFISH_OBJ.logout()
                back_file.close()
                return result
        return result
    else:
        error_message = utils.get_extended_error(response_manager_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            manager_url, response_manager_url.status, error_message)}
        REDFISH_OBJ.logout()
        back_file.close()
        return result


def add_helpmessage(parser):
    parser.add_argument('--backuppasswd', type=str, required=True, help='The password that you specified when the configuration was exported')
    parser.add_argument('--backupfile', type=str, required=True, help='An file that contains the configuration you wish to restore')


def add_parameter():
    """Add configuration restore parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["backuppasswd"] = args.backuppasswd
    parameter_info["backupfile"] = args.backupfile
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
    # BMC configuration restore and check result
    result = lenovo_config_restore(ip, login_account, login_password,backup_password,backup_file)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])

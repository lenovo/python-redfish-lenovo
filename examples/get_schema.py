###
#
# Lenovo Redfish examples - Get schema information
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


import sys, os
import redfish
import json
import traceback
import lenovo_utils as utils

def get_schema(ip, login_account, login_password, schema_prefix):
    """Get schema information
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params schema: Input the schema prefix get this schema uri or input the 'all' get all schema list
    :type schema: string
    :returns: returns get schema information result when succeeded or error message when failed
    """
    result = {}
    login_host = 'https://' + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    try:
        # Get ServiceRoot resource
        response_base_url = REDFISH_OBJ.get("/redfish/v1", None)
        if response_base_url.status == 200:
            Json_Schemas = response_base_url.dict['JsonSchemas']['@odata.id']
            response_json_schemas = REDFISH_OBJ.get(Json_Schemas, None)
            if response_json_schemas.status == 200:
                # Get the all schema list
                schema_list = response_json_schemas.dict['Members']
                schema_prefix = schema_prefix
                schema_uri_info = []
                if schema_prefix == 'all':
                    for schema in schema_list:
                        schema_url = schema["@odata.id"]
                        schema_prefix = schema_url.split('/')[-1]
                        response = REDFISH_OBJ.get(schema_url, None)
                        for location in response.dict["Location"]:
                            uri = location["Uri"]
                            response_uri = REDFISH_OBJ.get(uri, None)
                            if response_uri.status == 200:
                                filename = os.getcwd() + os.sep + uri.split("/")[-1]
                                schema = {}
                                msg = "Download schema file " + uri.split("/")[-1]
                                schema[schema_prefix] = msg
                                schema_uri_info.append(schema)
                                # save schema file
                                with open(filename, 'w') as f:
                                    json.dump(response_uri.dict, f, indent=2)
                            else:
                                schema = {}
                                msg = schema_prefix + " not found at " + uri
                                schema[schema_prefix] = msg
                                schema_uri_info.append(schema)
                else:
                    for schema in schema_list:
                        if schema_prefix in schema["@odata.id"]:
                            schema_url = schema["@odata.id"]
                            response = REDFISH_OBJ.get(schema_url, None)
                            for location in response.dict["Location"]:
                                uri = location["Uri"]
                                response_uri = REDFISH_OBJ.get(uri, None)
                                if response_uri.status == 200:
                                    filename = os.getcwd() + os.sep + uri.split("/")[-1]
                                    msg = "Download schema file " + uri.split("/")[-1]
                                    schema_uri_info.append(msg)
                                    # save schema file
                                    with open(filename, 'w') as f:
                                        json.dump(response_uri.dict, f, indent=2)
                                else:
                                    error_message = utils.get_extended_error(response_uri)
                                    result = {'ret': False,
                                              'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                                                  uri, response_uri.status, error_message)}
                                    return result
            else:
                error_message = utils.get_extended_error(response_json_schemas)
                result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                    Json_Schemas, response_json_schemas.status, error_message)}
                return result
        else:
            message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \n, Error message :%s" % (
            "/redfish/v1", response_base_url.status, message)}

        result['ret'] = True
        result['entries'] = schema_uri_info
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

import argparse
def add_parameter():
    """Add get schema parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--schema', type=str, required=True, help="Input the schema prefix get this schema uri or input the 'all' get all schema list")
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['schemaprefix'] = args.schema
    return parameter_info


if __name__ == '__main__':
     # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    schema_prefix = parameter_info['schemaprefix']

    # Get schema and check result
    result = get_schema(ip, login_account, login_password, schema_prefix)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])

###
#
# Lenovo Redfish examples - Get schema
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

def get_schema(ip, login_account, login_password, schema_prefix):
    """Get schema ingfo    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params ntp_server: ntp_server by user specified
    :type ntp_server: list
    :returns: returns set manager ntp result when succeeded or error message when failed
    """
    result = {}
    login_host = 'https://' + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')

        # Login into the server and create a session
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result
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
                            schema = {}
                            msg = "Found " + schema_prefix + " at " + uri
                            schema[schema_prefix] = msg
                            schema_uri_info.append(schema)
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
                                msg = "Found " + schema_prefix + " at " + uri
                                schema_uri_info.append(msg)
                            else:
                                result = {'ret': False, 'msg': schema_prefix + " not found at " + uri}
                                REDFISH_OBJ.logout()
                                return result
        else:
            result = {'ret': False, 'msg': "response json schemas Error code %s" % response_json_schemas.status}
            REDFISH_OBJ.logout()
            return result
    else:
        result = {'ret': False, 'msg': "Error code %s" % response_base_url.status}

    result['ret'] = True
    result['entries'] = schema_uri_info
    REDFISH_OBJ.logout()
    return result


import argparse
def add_parameter():
    """Add get schema parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--schema', type=str, help="Input the schema prefix get this schema uri or input the 'all' get all schema list")
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
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
        schema_prefix = parameter_info['schemaprefix']
    except:
        sys.stderr.write("Please run the coommand 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Get schema and check result
    result = get_schema(ip, login_account, login_password, schema_prefix)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
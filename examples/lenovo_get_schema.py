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


def get_schema(ip, login_account, login_password):
    result = {}
    # login_host = ip
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
            for schema in response_json_schemas.dict['Members']:
                schema_prefix = "ComputerSystem"
                if schema_prefix in schema["@odata.id"]:
                    response = REDFISH_OBJ.get(schema["@odata.id"], None)
                    for location in response.dict["Location"]:
                        uri = location["Uri"]
                        response_uri = REDFISH_OBJ.get(uri, None)
                        if response_uri.status == 200:
                            result = {'ret': True, 'msg':"Found " + schema_prefix + " at " + uri }
                        else:
                            result = {'ret': False, 'msg': schema_prefix + " not found at " + uri}
                            REDFISH_OBJ.logout()
                            return result
        else:
            result = {'ret': False, 'msg': "response json schemas Error code %s" % response_json_schemas.status}
            REDFISH_OBJ.logout()
            return result
    else:
        print("Error code %s" % response_base_url.status)
        result = {'ret': False, 'msg': "Error code %s" % response_base_url.status}

    REDFISH_OBJ.logout()
    return result


if __name__ == '__main__':
    # ip = '10.10.10.10'
    # login_account = 'USERID'
    # login_password = 'PASSW0RD'
    ip = sys.argv[1]
    login_account = sys.argv[2]
    login_password = sys.argv[3]
    result = get_schema(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
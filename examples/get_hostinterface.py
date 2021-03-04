###
#
# Lenovo Redfish examples - Get hostinterface inventory
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
import redfish
import json
import traceback
import lenovo_utils as utils

def get_hostinterface(ip, login_account, login_password):
    """Get hostinterface inventory    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :returns: returns hostinterface inventory when succeeded or error message when failed
    """
    result = {}
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        login_host = "https://" + ip
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check if the username, password, IP is correct."}
        return result

    # Get ServiceRoot resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    # Get response_telemetry_service_url
    if response_base_url.status != 200:
        result = {'ret': False, 'msg': "Access url /redfish/v1 failed. Error code %s" % response_base_url.status}
        REDFISH_OBJ.logout()
        return result

    # Get Managers colletion resource
    managers_url = response_base_url.dict["Managers"]['@odata.id']
    response_managers_url = REDFISH_OBJ.get(managers_url, None)
    if response_managers_url.status != 200:
        result = {'ret': False, 'msg': "Access url %s failed. Error code %s" % (managers_url, response_managers_url.status)}
        REDFISH_OBJ.logout()
        return result

    # Get each Manager resource
    hostinterfaces = []
    for request in response_managers_url.dict['Members']:
        request_url = request['@odata.id']
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % ( 
                request_url, response_url.status, error_message)}
            return result

        # Get HostInterfaces collection resource
        if "HostInterfaces" not in response_url.dict:
            continue
        hostinterfaces_url = response_url.dict["HostInterfaces"]['@odata.id']
        response_hostinterfaces_url = REDFISH_OBJ.get(hostinterfaces_url, None)
        if response_hostinterfaces_url.status != 200:
            error_message = utils.get_extended_error(response_hostinterfaces_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % ( 
                hostinterfaces_url, response_hostinterfaces_url.status, error_message)}
            return result

        # Get each HostInterface resource
        for interface in response_hostinterfaces_url.dict['Members']:
            request_url = interface['@odata.id']
            response_url = REDFISH_OBJ.get(request_url, None)
            if response_url.status != 200:
                error_message = utils.get_extended_error(response_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % ( 
                    request_url, response_url.status, error_message)}
                return result

            hostinterface_dict = {}
            for key in response_url.dict:
                if key not in ["Description","@odata.context","@odata.id","@odata.type","@odata.etag", "Links", "Actions", "RelatedItem",
                               "HostEthernetInterfaces", "ManagerEthernetInterface", "NetworkProtocol"]:
                    hostinterface_dict[key] = response_url.dict[key]

            # Get HostEthernetInterfaces resource
            if "HostEthernetInterfaces" not in response_url.dict:
                hostinterfaces.append(hostinterface_dict)
                continue

            # Get HostEthernetInterfaces resource
            hostethernets_url = response_url.dict["HostEthernetInterfaces"]['@odata.id']
            response_hostethernets_url = REDFISH_OBJ.get(hostethernets_url, None)
            if response_hostethernets_url.status != 200:
                error_message = utils.get_extended_error(response_hostethernets_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % ( 
                    hostethernets_url, response_hostethernets_url.status, error_message)}
                return result

            # Get each HostEthernetInterface resource
            HostEthernetInterfaces = []
            for ethernet in response_hostethernets_url.dict['Members']:
                request_url = ethernet['@odata.id']
                response_url = REDFISH_OBJ.get(request_url, None)
                if response_url.status != 200:
                    error_message = utils.get_extended_error(response_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % ( 
                        request_url, response_url.status, error_message)}
                    return result
                hostethernetinterface_dict = {}
                for key in response_url.dict:
                    if key not in ["Description","@odata.context","@odata.id","@odata.type","@odata.etag", "Links", "Actions", "RelatedItem"]:
                        hostethernetinterface_dict[key] = response_url.dict[key]
                HostEthernetInterfaces.append(hostethernetinterface_dict)

            hostinterface_dict["HostEthernetInterfaces"] = HostEthernetInterfaces
            hostinterfaces.append(hostinterface_dict)
            continue


    result['ret'] = True
    result['hostinterfaces'] = hostinterfaces

    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result


def add_parameter():
    argget = utils.create_common_parameter_list()
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

    # Get hostinterface inventory and check result
    result = get_hostinterface(ip, login_account, login_password)

    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['hostinterfaces'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')

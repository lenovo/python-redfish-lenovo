###
#
# Lenovo Redfish examples - get virtual media
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


import redfish
import sys
import json
import traceback
import lenovo_utils as utils


def get_virtual_media(ip, login_account, login_password):
    """Get virtual media
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :returns: returns get virtual media list when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    try:
        # Get ComputerBase resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        # Get response_base_url
        if response_base_url.status == 200:
            managers_url = response_base_url.dict['Managers']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '/redfish/v1' response Error code %s \nerror_message: %s" % (
            response_base_url.status, error_message)}
            return result

        # Get response managers url resource
        virtual_media_info_list = []
        response_managers_url = REDFISH_OBJ.get(managers_url, None)
        if response_managers_url.status == 200:
            # Get the virtual media url
            for i in range(response_managers_url.dict['Members@odata.count']):
                manager_x_url = response_managers_url.dict['Members'][i]['@odata.id']
                response_manager_x_url = REDFISH_OBJ.get(manager_x_url, None)
                if response_manager_x_url.status == 200:
                    virtual_media_url = response_manager_x_url.dict["VirtualMedia"]["@odata.id"]
                else:
                    error_message = utils.get_extended_error(response_manager_x_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        manager_x_url, response_manager_x_url.status, error_message)}
                    return result

                # Get the virtual media response resource
                response_virtual_media = REDFISH_OBJ.get(virtual_media_url, None)
                if response_virtual_media.status == 200:
                    members_count = response_virtual_media.dict["Members@odata.count"]
                    if members_count == 0:
                        result = {"ret": True, "entries":"This server doesn't mount virtual media."}
                        return result

                    # Loop all the virtual media members and get all the virtual media informations
                    for i in range(members_count):
                        virtual_media_info = {}
                        virtual_media_x_url = response_virtual_media.dict["Members"][i]["@odata.id"]
                        response_virtual_media_x_url = REDFISH_OBJ.get(virtual_media_x_url, None)
                        if response_virtual_media_x_url.status == 200:
                            for property in ['Id', 'Name', 'ConnectedVia', 'MediaTypes', 'Image', 'ImageName', 'WriteProtected']:
                                if property in response_virtual_media_x_url.dict:
                                    virtual_media_info[property] = response_virtual_media_x_url.dict[property]
                            virtual_media_info_list.append(virtual_media_info)
                        else:
                            error_message = utils.get_extended_error(response_virtual_media_x_url)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                                virtual_media_x_url, response_virtual_media_x_url.status, error_message)}
                            return result

                # Return error messages when the virtual media url response failed
                else:
                    error_message = utils.get_extended_error(response_virtual_media)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        virtual_media_url, response_virtual_media.status, error_message)}
                    return result

        # Return error messages when the managers url response failed
        else:
            error_message = utils.get_extended_error(response_managers_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (managers_url, response_managers_url.status, error_message)}
            return result

        result['ret'] = True
        result['entries'] = virtual_media_info_list

    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "error_message: %s" % e}
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    argget = utils.create_common_parameter_list()
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get virtual media info and check result
    result = get_virtual_media(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])

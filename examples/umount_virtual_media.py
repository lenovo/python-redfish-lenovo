###
#
# Lenovo Redfish examples - eject vitual media
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

###
#
# This script only works on the latest XCC Firmware of lenovo (2.50 and above).
# You can check "version" property of the URI below:
#     https://ip/redfish/v1/UpdateService/FirmwareInventory/BMC-Primary
#
# If your version is lower than it, you can use the script below, which works on old XCC Firmware.
#     https://github.com/lenovo/python-redfish-lenovo/blob/master/examples/lenovo_umount_virtual_media.py
#
###


import sys
import redfish
import json
import lenovo_utils as utils


def eject_virtual_media(ip, login_account, login_password, image):
    """Mount an ISO or IMG image file from a file server to the host as a DVD or USB drive.
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params image: This value shall specify the eject virtual media image mame
    :type image:string
    :returns: returns eject virtual media iso result when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    # Login into the server
    try:
        # Connect using the address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        REDFISH_OBJ.login(auth="basic")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    try:
        # Get ServiceRoot resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)

        # Get Managers resource
        if response_base_url.status == 200:
            managers_url = response_base_url.dict['Managers']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': " Url '/redfish/v1' response Error code %s \nerror_message: %s" % (
            response_base_url.status, error_message)}
            return result

        response_managers_url = REDFISH_OBJ.get(managers_url, None)
        if response_managers_url.status == 200:
            # Get manager url form manager resource instance
            count = response_managers_url.dict['Members@odata.count']
            for i in range(count):
                manager_url = response_managers_url.dict['Members'][i]['@odata.id']
                response_manager_url = REDFISH_OBJ.get(manager_url, None)
                if response_manager_url.status == 200:
                    # Get the virtual media url from the manger response
                    virtual_media_url = response_manager_url.dict['VirtualMedia']['@odata.id']
                else:
                    error_message = utils.get_extended_error(response_manager_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        manager_url, response_manager_url.status, error_message)}
                    return result

                # Get the mount virtual media list
                # For the latest XCC Firmware(version is 2.5 and above), there are 10 predefined members
                response_virtual_media = REDFISH_OBJ.get(virtual_media_url, None)
                if response_virtual_media.status == 200:
                    members_list = response_virtual_media.dict["Members"]
                else:
                    error_message = utils.get_extended_error(response_virtual_media)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        virtual_media_url, response_virtual_media.status, error_message)}
                    return result

                # Get the mount virtual media list
                for members in members_list:
                    members_url = members["@odata.id"]
                    if not members_url.split('/')[-1].startswith("Remote"):
                        response_members = REDFISH_OBJ.get(members_url, None)
                        if response_members.status == 200:
                            image_name = response_members.dict["ImageName"]
                        else:
                            error_message = utils.get_extended_error(response_members)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                                members_url, response_members.status, error_message)}
                            return result
                        if image_name == image:
                            body = {"Image": None}
                            response = REDFISH_OBJ.patch(members_url, body=body)
                            if response.status in [200,204]:
                                result = {'ret': True, 'msg': "'%s' Umount successfully" % image}
                                return result
                            else:
                                error_message = utils.get_extended_error(response_managers_url)
                                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                                    members_url, response.status, error_message)}
                                return result
                        else:
                            continue
                result = {"ret": False, "msg": "Please check the image name is correct and has been mounted."}
                return result
        else:
            error_message = utils.get_extended_error(response_managers_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
            managers_url, response_managers_url.status, error_message)}
    except Exception as e:
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
    finally:
        # Logout
        REDFISH_OBJ.logout()
        return result


def add_helpmessage(argget):
    argget.add_argument('--image', type=str, required=True, help='Input the umount virtual media name')


def add_parameter():
    """Add mount media iso parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['image'] = args.image
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get mount media iso info from the parameters user specified
    try:
        image = parameter_info['image']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Get mount media iso result and check result
    result = eject_virtual_media(ip, login_account, login_password, image)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])

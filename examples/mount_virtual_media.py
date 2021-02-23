###
#
# Lenovo Redfish examples - Insert vitual media
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
#     https://github.com/lenovo/python-redfish-lenovo/blob/master/examples/lenovo_mount_virtual_media.py
#
###

import sys
import redfish
import json
import traceback
import lenovo_utils as utils


def mount_virtual_media(ip, login_account, login_password, fsprotocol, fsip, fsport, image, fsdir, inserted, writeprotocol):
    """Mount an ISO or IMG image file from a file server to the host as a DVD or USB drive.
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :type fsip:string
    :params fsip:Specify the file server ip
    :type fsdir:string
    :params fsdir:File path of the image
    :type image:string
    :params inserted:This value shall specify if the image is to be treated as inserted upon completion of the action. If this parameter is not provided by the client, the service shall default this value to be true.
    :type inserted: int
    :params writeProtected:This value shall specify if the remote media is supposed to be treated as write protected. If this parameter is not provided by the client, the service shall default this value to be true
    :type writeProtected: int
    :returns: returns mount media iso result when succeeded or error message when failed
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
        traceback.print_exc()
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

                # Get the members url from the members list
                for members in members_list:
                    members_url = members["@odata.id"]
                    if members_url.split('/')[-1].startswith("EXT"):

                        # Get the mount image name from the members response resource
                        response_members = REDFISH_OBJ.get(members_url, None)
                        if response_members.status == 200:
                            image_name = response_members.dict["ImageName"]
                        else:
                            error_message = utils.get_extended_error(response_members)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                                members_url, response_members.status, error_message)}
                            return result

                        # Via patch request mount virtual media
                        port = (lambda fsport: ":" + fsport if fsport else fsport)
                        dir = (lambda fsdir: "/" + fsdir.strip("/") if fsdir else fsdir)
                        protocol = fsprotocol.lower()
                        fsport = port(fsport)
                        fsdir = dir(fsdir)
                        if image_name is None:
                            if protocol == "nfs":
                                image_uri = fsip + fsport + ":" + fsdir + "/" + image
                            else:
                                image_uri = protocol + "://" + fsip + fsport + fsdir + "/" + image
                            body = {"Image": image_uri, "WriteProtected": bool(writeprotocol),
                                    "Inserted": bool(inserted)}
                            response = REDFISH_OBJ.patch(members_url, body=body)
                            if response.status in [200, 204]:
                                result = {'ret': True, 'msg': "'%s' mount successfully" % image}
                                return result
                            else:
                                error_message = utils.get_extended_error(response)
                                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                                    members_url, response.status, error_message)}
                                return result
                        else:
                            continue
                result = {'ret': False, 'msg': "Up to 4 files can be concurrently mounted to the server by the BMC."}
                return result
        else:
            error_message = utils.get_extended_error(response_managers_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
            managers_url, response_managers_url.status, error_message)}
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
    finally:
        # Logout
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


def add_helpmessage(argget):
    argget.add_argument('--fsprotocol', type=str, nargs='?', choices=["NFS", "HTTP", "HTTPS"],
                        help='Specifies the protocol prefix for uploading image or ISO. Support: ["NFS","HTTP","HTTPS"]')
    argget.add_argument('--fsip', type=str, help='Specify the file server ip')
    argget.add_argument('--fsdir', type=str, help='File path of the image')
    argget.add_argument('--fsport', type=str, default='', help='Specify the file server port')
    argget.add_argument('--image', type=str, required=True, help='Mount media iso name')
    argget.add_argument('--inserted', type=int, nargs='?', default=1, choices=[0, 1],
                        help='Indicates if virtual media is inserted in the virtual device. Support: [0:False, 1:True].')
    argget.add_argument('--writeprotocol', type=int, nargs='?', default=1, choices=[0, 1],
                        help='Indicates the media is write protected. Support: [0:False, 1:True].')


import configparser
import os
def add_parameter():
    """Add mount media iso parameter"""
    argget = utils.create_common_parameter_list(example_string='''
Example of HTTP/NFS:
  "python mount_virtual_media.py -i 10.10.10.10 -u USERID -p PASSW0RD --fsprotocol HTTP --fsip 10.10.10.11 --fsdir /fspath/ --image isoname.img"
''')
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    config_file = args.config
    config_ini_info = utils.read_config(config_file)

    # Add FileServerCfg parameter to config_ini_info
    cfg = configparser.ConfigParser()
    if os.path.exists(config_file):
        cfg.read(config_file)
        config_ini_info["fsprotocol"] = cfg.get('FileServerCfg', 'FSprotocol')
        config_ini_info["fsip"] = cfg.get('FileServerCfg', 'FSip')
        config_ini_info["fsport"] = cfg.get('FileServerCfg', 'FSport')
        config_ini_info["fsdir"] = cfg.get('FileServerCfg', 'FSdir')

    # Gets the parameters specified on the command line
    parameter_info['image'] = args.image
    parameter_info['inserted'] = args.inserted
    parameter_info['writeprotocol'] = args.writeprotocol

    # Parse the added parameters
    parameter_info['fsprotocol'] = args.fsprotocol
    parameter_info['fsport'] = args.fsport
    parameter_info['fsip'] = args.fsip
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

    # Get mount media iso info from the parameters user specified
    try:
        fsprotocol = parameter_info['fsprotocol']
        fsip = parameter_info['fsip']
        fsport = parameter_info['fsport']
        image = parameter_info['image']
        fsdir = parameter_info['fsdir']
        inserted = parameter_info['inserted']
        writeprotocol = parameter_info['writeprotocol']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Get mount media iso result and check result
    result = mount_virtual_media(ip, login_account, login_password, fsprotocol, fsip, fsport, image, fsdir, inserted, writeprotocol)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

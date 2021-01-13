###
#
# Lenovo Redfish examples - Mount vitual media
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

import traceback
import sys
import redfish
import json
import time
import lenovo_utils as utils


def lenovo_mount_virtual_media(ip, login_account, login_password, image, mounttype, fsprotocol, fsip, fsport, fsusername, fspassword, fsdir, readonly, domain, options, inserted, writeprotocol):
    """Mount virtual media, supporting both 18D and 19A version of Lenovo XCC.
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params image: Mount virtual media name
    :type image:string
    :param mounttype: Types of mount virtual media.
    :type mounttype:string
    :params fsprotocol:Specifies the protocol prefix for uploading image or ISO
    :type fsprotocol: string
    :params fsip:Specify the file server ip
    :type fsip: string
    :params fsusername:Username to access the file path, available for Samba, NFS, HTTP, SFTP/FTP
    :type fsusername: string
    :params fspassword:Password to access the file path, password should be encrypted after object creation, available for Samba, NFS, HTTP, SFTP/FTP
    :type fspassword: string
    :params fsdir:File path of the map image
    :type fsdir: string
    :params readonly:It indicates the map image status is readonly or read/write
    :type readonly: string
    :params domain:Domain of the username to access the file path, available for Samba only.
    :type domain: string
    :params options:It indicates the mount options to map the image of the file path, available for Samba and NFS only
    :type options: string
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
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    try:
        # Get ServiceRoot resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)

        # Get response_account_service_url
        if response_base_url.status == 200:
            account_managers_url = response_base_url.dict['Managers']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': " Url '/redfish/v1' response Error code %s \nerror_message: %s" % (
            response_base_url.status, error_message)}
            return result

        response_managers_url = REDFISH_OBJ.get(account_managers_url, None)
        if response_managers_url.status == 200:
            # Get manager url form manager resource instance
            count = response_managers_url.dict['Members@odata.count']
            for i in range(count):
                manager_url = response_managers_url.dict['Members'][i]['@odata.id']
                response_manager_url = REDFISH_OBJ.get(manager_url, None)
                if response_manager_url.status == 200:
                    # Get the virtual media url from the manger response
                    virtual_media_url = response_manager_url.dict['VirtualMedia']['@odata.id']
                    # Get mount media iso url
                    remotemap_url = ""
                    remotecontrol_url = ""
                    if "Oem" in response_manager_url.dict:
                        Oem_dict = response_manager_url.dict['Oem']
                        if "Ami" in Oem_dict:
                            # SR635/SR655  Enable VirtualMedia
                            MediaStatus = Oem_dict['Ami']['VirtualMedia']['RMediaStatus']
                            Enable_Media_url = response_manager_url.dict["Actions"]["Oem"]["#AMIVirtualMedia.EnableRMedia"]["target"]

                            # Check the CIFS is supported for SR635 / SR655 products
                            if fsprotocol.upper() == 'CIFS':
                                meidaAction_url = virtual_media_url + '/' + 'CD1' + '/' + 'InsertMediaActionInfo'
                                respones_mediaAction_url = REDFISH_OBJ.get(meidaAction_url, None)
                                for parameter in respones_mediaAction_url.dict['Parameters']:
                                    if parameter['Name'] == 'TransferProtocolType':
                                        support_type = parameter['AllowableValues']
                                        if fsprotocol.upper() not in support_type:
                                            result = {'ret': False,
                                                      'msg': "SR635/SR655 products only supports the NFS protocol to mount virtual media."}
                                            return result

                            # Enable remote media support
                            if MediaStatus != "Enabled":
                                body = {"RMediaState": "Enable"}
                                response_enable_url = REDFISH_OBJ.post(Enable_Media_url, body=body)
                                if response_enable_url.status in [200, 204]:
                                    time.sleep(10)
                                    print("Enable remote media support")
                                else:
                                    error_message = utils.get_extended_error(response_enable_url)
                                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                                              Enable_Media_url, response_enable_url.status, error_message)}
                                    return result
                        elif "Lenovo" in Oem_dict:
                            # XCC Mount VirtualMedia
                            remotemap_url = Oem_dict['Lenovo']['RemoteMap']['@odata.id']
                            remotecontrol_url = Oem_dict['Lenovo']['RemoteControl']['@odata.id']
                        else:
                            result = {'ret': False, 'msg': "Please check whether the redfish version supports mount virtual media."}
                            return result
                    else:
                        # Get Oem EnableRMedia url
                        ActionsKeys = response_manager_url.dict["Actions"].keys()
                        if "Oem" in ActionsKeys:
                            Enable_Media_url = response_manager_url.dict["Actions"]["Oem"]["#VirtualMedia.EnableRMedia"]["target"]
                            MediaStatus = response_manager_url.dict["Actions"]["Oem"]["#VirtualMedia.EnableRMedia"]["Status"]
                            CdInstance_url = response_manager_url.dict["Actions"]["Oem"]["#VirtualMedia.ConfigureCDInstance"]["target"]
                            CdInstance = response_manager_url.dict["Actions"]["Oem"]["#VirtualMedia.ConfigureCDInstance"]["CDInstances"]
                        else:
                            result = {'ret': False, 'msg': "Please check whether the redfish version supports mount virtual media."}
                            return result
                    
                        # Enable remote media support
                        if MediaStatus != "Enabled":
                            body = {"RMediaState": "Enable"}
                            response_enable_url = REDFISH_OBJ.post(Enable_Media_url, body=body)
                            if response_enable_url.status in [200, 204]:
                                time.sleep(10)
                                print('Enable remote media support')
                            else:
                                error_message = utils.get_extended_error(response_enable_url)
                                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        Enable_Media_url, response_enable_url.status, error_message)}
                                return result
                        
                        # Set the CdInstace
                        if CdInstance != 4:
                            body = {"CDInstance": 4}
                            response = REDFISH_OBJ.post(CdInstance_url, body=body)
                            if response.status in [200, 204]:
                                sys.stdout.write("The RMedia will be restart, wait a moment...")
                                secs = 180
                                while secs:
                                    flush()
                                    secs -= 1
                            elif response.status == 400:
                                result = {'ret': False, 'msg': "Stop all the active media redirections and Re-execute the script"}
                                return result
                            else:
                                error_message = utils.get_extended_error(response)
                                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                                CdInstance_url, response.status, error_message)}
                                return result
                        
                else:
                    error_message = utils.get_extended_error(response_manager_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        manager_url, response_manager_url.status, error_message)}
                    return result

                # Get the mount virtual media list
                response_virtual_media = REDFISH_OBJ.get(virtual_media_url, None)
                if response_virtual_media.status == 200:
                    members_list = response_virtual_media.dict["Members"]
                else:
                    error_message = utils.get_extended_error(response_virtual_media)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        virtual_media_url, response_virtual_media.status, error_message)}
                    return result

                # Define an anonymous function formatting parameter
                port = (lambda fsport: ":" + fsport if fsport else fsport)
                dir = (lambda fsdir: "/" + fsdir.strip("/") if fsdir else fsdir)
                protocol = fsprotocol.lower()
                fsport = port(fsport)
                fsdir = dir(fsdir)
                if protocol == "samba":
                    source_url = "smb://" + fsip + fsport + fsdir + "/" + image
                else:
                    source_url = protocol + "://" + fsip + fsport + fsdir + "/" + image
                # Build file server image url
                if mounttype == "Network":
                    # for 19A, XCC predefined 10 members, so call mount function for 19A. otherwise, call function for 18D.
                    if len(members_list) == 10:
                        if fsprotocol in ["NFS", "HTTP"]:
                            result = mount_virtual_media(REDFISH_OBJ, members_list, protocol, fsip, fsport, fsdir, image, writeprotocol, inserted)
                            return result
                        else:
                            result = {"ret": False, "msg": "For remote mounts, only HTTP and NFS(no credential required) protocols are supported."}
                            return result
                    elif len(members_list) == 4:
                        if fsprotocol in ["NFS", "CIFS"]:
                            result = mount_virtual_media_from_cd(REDFISH_OBJ, members_list, protocol, fsip, fsport, fsdir, image, fsusername, fspassword)
                            return result
                        else:
                            result = {"ret": False, "msg": "For remote mounts, only NFS(no credential required) and CIFS protocols are supported."}
                            return result 
                    else:
                        result = mount_virtual_media_from_network(REDFISH_OBJ, remotemap_url, image, fsip, fsport, fsdir,
                                                                  fsprotocol, fsusername, fspassword, readonly, domain,
                                                                  options)
                        return result
                else:
                    result = mount_virtual_media_from_rdoc(REDFISH_OBJ, remotecontrol_url, remotemap_url,  source_url, fsusername, fspassword, fsprotocol, readonly, domain, options)
                    return result
        else:
            error_message = utils.get_extended_error(response_managers_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
            account_managers_url, response_managers_url.status, error_message)}
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
        return result
    finally:
        # Logout
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


def flush():
    list = ['|', '\\', '-', '/']
    for i in list:
        sys.stdout.write(' ' * 100 + '\r')
        sys.stdout.flush()
        sys.stdout.write(i + '\r')
        sys.stdout.flush()
        time.sleep(0.1)


def mount_virtual_media_from_cd(REDFISH_OBJ, members_list, protocol, fsip, fsport, fsdir, image, fsusername=None, fspassword=None):
    """
    This function user the post method to mount VM, only NFS protocols are supported.
    This function can work on AMD server.
    """
    # Get the members url from the members list
    if not image.endswith(".iso") and not image.endswith(".nrg"):
        result = {'ret': False, 'msg': "Supported CD/DVD media file type: (*.iso), (*.nrg)."}
        return result

    for members in members_list:
        members_url = members["@odata.id"]
        # Get the mount image name from the members response resource
        response_members = REDFISH_OBJ.get(members_url, None)
        if response_members.status == 200:
            image_name = response_members.dict["ImageName"]
            InsertMedia_url = response_members.dict["Actions"]["#VirtualMedia.InsertMedia"]["target"]
        else:
            error_message = utils.get_extended_error(response_members)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                members_url, response_members.status, error_message)}
            return result

        if not image_name:
            image_uri = protocol + "://" + fsip + fsport + fsdir + "/" + image
            if protocol == 'nfs':
                body = {"Image": image_uri, "TransferProtocolType": protocol.upper()}
            else:
                body = {"Image": image_uri, "TransferProtocolType": protocol.upper(), "UserName": fsusername, "Password": fspassword}
            response = REDFISH_OBJ.post(InsertMedia_url, body=body)
            if response.status in [200, 204]:
                result = {'ret': True, 'msg': "'%s' mount successfully" % image}
                return result
            else:
                error_message = utils.get_extended_error(response)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                    InsertMedia_url, response.status, error_message)}
                return result
        else:
            continue
    result = {'ret': False, 'msg': "Up to 4 files can be concurrently mounted to the server by the BMC."}
    return result


def mount_virtual_media(REDFISH_OBJ, members_list, protocol, fsip, fsport, fsdir, image, writeprotocol, inserted):
    """
     This function uses the patch method to mount VM, only HTTP and NFS(no credential required) protocols are supported.
     This function can work on 19A version of XCC and license is "Lenovo XClarity Controller Enterprise".
    """
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
            if image_name is None:
                if protocol == "nfs":
                    image_uri = fsip + fsport + ":" + fsdir + "/" + image
                else:
                    image_uri = protocol + "://" + fsip + fsport + fsdir + "/" + image
                body = {"Image": image_uri, "WriteProtected": bool(writeprotocol), "Inserted": bool(inserted)}
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


def mount_virtual_media_from_rdoc(REDFISH_OBJ, remotecontrol_url, remotemap_url,  source_url, fsusername, fspassword, fsprotocol, readonly, domain, options):
    """
    This function use the Lenovo OEM extensions for VM mount, support mounting 2 RDOC images and maximum amount sizes of RDOC images are 50MB.
    This function can work on 18D version of XCC and license is "Lenovo XClarity Controller Advanced".
    """
    # Upload the mount image via file server
    response_remotecontrol_url = REDFISH_OBJ.get(remotecontrol_url, None)
    if response_remotecontrol_url.status == 200:
        # Get upload media iso url from remoto control resource instance
        upload_url = response_remotecontrol_url.dict['Actions']['#LenovoRemoteControlService.UploadFromURL']['target']
        body = {"sourceURL": source_url, "Username": fsusername, "Password": fspassword, "Type": fsprotocol,
                "Readonly": bool(readonly), "Domain": domain, "Options": options}
        response_upload_url = REDFISH_OBJ.post(upload_url, body=body)
        if response_upload_url.status in [200, 204]:
            print("Upload media iso successful, next will mount media iso...")
        else:
            error_message = utils.get_extended_error(response_upload_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
            upload_url, response_upload_url.status, error_message)}
            return result
    else:
        error_message = utils.get_extended_error(response_remotecontrol_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
            remotecontrol_url, response_remotecontrol_url.status, error_message)}
        return result

    # Mount the virtual media
    response_remotemap_url = REDFISH_OBJ.get(remotemap_url, None)
    if response_remotemap_url.status == 200:
        # Get mount image url form remote map resource instance
        mount_image_url = response_remotemap_url.dict['Actions']['#LenovoRemoteMapService.Mount']['target']

        response_mount_image = REDFISH_OBJ.post(mount_image_url, None)
        if response_mount_image.status in [200, 204]:
            result = {'ret': True, 'msg': "'%s' mount successfully" % image}
            return result
        else:
            error_message = utils.get_extended_error(response_mount_image)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
            mount_image_url, response_mount_image.status, error_message)}
            return result
    else:
        error_message = utils.get_extended_error(response_remotemap_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
        remotemap_url, response_remotemap_url.status, error_message)}
        return result


def mount_virtual_media_from_network(REDFISH_OBJ, remotemap_url, image, fsip, fsport, fsdir, fsprotocol, fsusername, fspassword, readonly, domain, options):
    """
    This function use the Lenovo OEM extensions for virtual media mount, support mounting up to 4 images concurrently to the server.
    This function can work on 18D version of XCC and license is "Lenovo XClarity Controller Enterprise".
    """
    response_remotemap_url = REDFISH_OBJ.get(remotemap_url, None)
    if response_remotemap_url.status == 200:
        # Get MountImages url from remote map resource instance
        images_member_url = response_remotemap_url.dict['MountImages']['@odata.id']
        headers = {"Content-Type": "application/json"}

        # Build request body for add images member
        body = {}
        protocol = fsprotocol.lower()

        if protocol == "nfs":
            body["FilePath"] = fsip + fsport + ":" + fsdir + "/" + image
        elif protocol == "samba":
            body["FilePath"] = "//" + fsip + fsport + fsdir + "/" + image
        elif protocol in ['sftp', 'ftp', 'http']:
            body["FilePath"] = protocol + "://" + fsip + fsport + fsdir + "/" + image
        else:
            result = {'ret': False,
                      'msg': 'Mount media iso network only support protocol Samba, NFS, HTTP, SFTP/FTP'}
            return result
        body["Type"] = fsprotocol
        body["Username"] = fsusername
        body["Password"] = fspassword
        body["Domain"] = domain
        body["Readonly"] = bool(readonly)
        body["Options"] = options

        # Add image member
        response_images_member = REDFISH_OBJ.post(images_member_url, headers=headers, body=body)
        if response_images_member.status in [200, 201, 204]:
            print("Add image member successful.")
        else:
            error_message = utils.get_extended_error(response_images_member)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
            images_member_url, response_images_member.status, error_message)}
            return result

        # Get mount image url form remote map resource instance
        mount_image_url = response_remotemap_url.dict['Actions']['#LenovoRemoteMapService.Mount']['target']
        response_mount_image = REDFISH_OBJ.post(mount_image_url, None)
        if response_mount_image.status in [200, 204]:
            result = {'ret': True, 'msg': "'%s' mount successfully" % image}
            return result
        else:
            error_message = utils.get_extended_error(response_mount_image)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
            mount_image_url, response_mount_image.status, error_message)}
            return result
    else:
        error_message = utils.get_extended_error(response_remotemap_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
        remotemap_url, response_remotemap_url.status, error_message)}
        return result


def add_helpmessage(argget):
    argget.add_argument('--image', type=str, required=True, help='Mount virtual media name')
    argget.add_argument('--mounttype', type=str, default="Network", choices=["Network", "RDOC"], help="Types of mount virtual media.")

    argget.add_argument('--fsprotocol', type=str, nargs='?',choices=["Samba", "NFS", "CIFS", "HTTP", "SFTP", "FTP"],
                        help='Specifies the protocol prefix for uploading image or ISO. '
                             'For SR635 / SR655 products, only support: ["NFS", "CIFS"], for other products, support:["Samba", "NFS", "HTTP", "SFTP", "FTP"]. ')
    argget.add_argument('--fsip', type=str, nargs='?', help='Specify the file server ip')
    argget.add_argument('--fsport', type=str, default='', help='Specify the file server port')
    argget.add_argument('--fsusername', type=str, nargs='?',
                        help='Username to access the file path, available for Samba, CIFS, HTTP, SFTP/FTP')
    argget.add_argument('--fspassword', type=str, nargs='?',
                        help='Password to access the file path, password should be encrypted after object creation, available for Samba, CIFS, HTTP, SFTP/FTP')
    argget.add_argument('--fsdir', type=str, nargs='?', help='File path of the image')

    argget.add_argument('--readonly', type=int, nargs='?', default=1, choices=[0, 1],
                        help='It indicates the image is mapped as readonly or read/write. Support: [0:False, 1:True].')
    argget.add_argument('--domain', type=str, nargs='?', default='',
                        help='Domain of the username to access the file path, available for Samba only.')
    argget.add_argument('--options', type=str, nargs='?', default='',
                        help='It indicates the mount options to map the image of the file path, available for Samba and NFS only.')
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
  "python lenovo_mount_virtual_media.py -i 10.10.10.10 -u USERID -p PASSW0RD --fsprotocol HTTP --fsip 10.10.10.11 --fsdir /fspath/ --image isoname.img"
Example of SFTP/FTP/Samba:
  "python lenovo_mount_virtual_media.py -i 10.10.10.10 -u USERID -p PASSW0RD --fsprotocol SFTP --fsip 10.10.10.11 --fsusername mysftp --fspassword mypass --fsdir /fspath/ --image isoname.img"
''')
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
        config_ini_info["fsport"] = cfg.get('FileServerCfg', 'FSport')
        config_ini_info["fsusername"] = cfg.get('FileServerCfg', 'FSusername')
        config_ini_info["fspassword"] = cfg.get('FileServerCfg', 'FSpassword')
        config_ini_info["fsdir"] = cfg.get('FileServerCfg', 'FSdir')

    # Get the user specify parameter from the command line
    parameter_info = utils.parse_parameter(args)
    parameter_info["image"] = args.image
    parameter_info["mounttype"] = args.mounttype
    parameter_info['fsprotocol'] = args.fsprotocol
    parameter_info['fsip'] = args.fsip
    parameter_info['fsport'] = args.fsport
    parameter_info['fsusername'] = args.fsusername
    parameter_info['fspassword'] = args.fspassword
    parameter_info['fsdir'] = args.fsdir

    parameter_info['readonly'] = args.readonly
    parameter_info['domain'] = args.domain
    parameter_info['options'] = args.options
    parameter_info['inserted'] = args.inserted
    parameter_info['writeprotocol'] = args.writeprotocol

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
        image = parameter_info['image']
        mounttype = parameter_info['mounttype']
        fsprotocol = parameter_info['fsprotocol']
        fsip = parameter_info['fsip']
        fsport = parameter_info['fsport']
        fsusername = parameter_info['fsusername']
        fspassword = parameter_info['fspassword']
        fsdir = parameter_info['fsdir']
        readonly = parameter_info['readonly']
        domain = parameter_info['domain']
        options = parameter_info['options']
        inserted = parameter_info['inserted']
        writeprotocol = parameter_info['writeprotocol']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Get mount media iso result and check result

    result = lenovo_mount_virtual_media(ip, login_account, login_password, image, mounttype, fsprotocol, fsip, fsport, fsusername, fspassword, fsdir, readonly, domain, options, inserted, writeprotocol)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

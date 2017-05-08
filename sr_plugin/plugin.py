"""
 Copyright (C) Citrix Systems Inc.

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published
 by the Free Software Foundation; version 2.1 only.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public License
 along with this program; if not, write to the Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

 plugin: A SMAPIv3 to SMAPIv1 conversion layer that allows writing SMAPIv3
         style SRs
"""

import errno
import exceptions
import subprocess
import sys
import syslog
import traceback
import xmlrpclib
import XenAPI

MIN_VDI_SIZE = 512  # 512 bytes
MAX_VDI_SIZE = 16 * 1024 * 1024 * 1024 * 1024  # 16TB


def log(message, level=syslog.LOG_INFO):
    syslog.openlog(None, syslog.LOG_PID, syslog.LOG_LOCAL2)
    syslog.syslog(level, message)
    syslog.closelog()


def main(SR, Volume, Datapath, DRIVER_INFO):
    try:
        params, cmd = xmlrpclib.loads(sys.argv[1])

        if cmd == 'sr_get_driver_info':
            results = {}
            for key in ['name', 'description', 'vendor', 'copyright',
                        'driver_version', 'required_api_version',
                        'capabilities']:
                results[key] = DRIVER_INFO[key]
            options = []
            for option in DRIVER_INFO['configuration']:
                options.append({'key': option[0], 'description': option[1]})
            results['configuration'] = options
            print xmlrpclib.dumps((results,), "", True)
            sys.exit(0)

        params = params[0]
        dconf = params['device_config']
        if 'sr_uuid' in params:
            sr_uuid = params['sr_uuid']
        if 'vdi_uuid' in params:
            vdi_uuid = params['vdi_uuid']
        if 'vdi_location' in params:
            vdi_location = params['vdi_location']

        dbg = "Dummy"
        session = XenAPI.xapi_local()
        session._session = params['session_ref']

        def db_introduce(v, uuid):
            sm_config = {}
            ty = "user"
            is_a_snapshot = False
            metadata_of_pool = "OpaqueRef:NULL"
            snapshot_time = "19700101T00:00:00Z"
            snapshot_of = "OpaqueRef:NULL"
            shareable = True
            sr_ref = session.xenapi.SR.get_by_uuid(sr_uuid)
            read_only = False
            managed = True
            session.xenapi.VDI.db_introduce(uuid,
                                            v['name'],
                                            v['description'],
                                            sr_ref,
                                            ty,
                                            shareable,
                                            read_only,
                                            {},
                                            v['uri'][0],
                                            {},
                                            sm_config,
                                            managed,
                                            str(v['virtual_size']),
                                            str(v['virtual_size']),
                                            metadata_of_pool,
                                            is_a_snapshot,
                                            xmlrpclib.DateTime(snapshot_time),
                                            snapshot_of)

        def db_forget(uuid):
            vdi = session.xenapi.VDI.get_by_uuid(uuid)
            session.xenapi.VDI.db_forget(vdi)

        def sr_update(sr_ref):
            stats = SR().stat(dbg, sr_uuid)
            session.xenapi.SR.set_virtual_allocation(
                sr_ref, str(stats["virtual_allocation"]))
            session.xenapi.SR.set_physical_size(
                sr_ref, str(stats["physical_size"]))
            session.xenapi.SR.set_physical_utilisation(
                sr_ref, str(stats["physical_utilisation"]))

        def vdi_update():
            vdi_ref = session.xenapi.VDI.get_by_uuid(vdi_uuid)
            # Update name and description
            name = session.xenapi.VDI.get_name_label(vdi_ref)
            description = session.xenapi.VDI.get_name_description(vdi_ref)
            # Get volume stats and update XAPI
            stats = Volume().stat(dbg, sr_uuid, vdi_uuid)
            if 'virtual_size' in stats:
                session.xenapi.VDI.set_virtual_size(vdi_ref,
                                                    str(stats["virtual_size"]))
            if 'physical_utilisation' in stats:
                session.xenapi.VDI.set_physical_utilisation(
                    vdi_ref, str(stats["physical_utilisation"]))
            # Update the on-disk name and description if needed
            if name != stats['name']:
                Volume().set_name(dbg, sr_uuid, vdi_uuid, name)
            if description != stats['description']:
                Volume().set_description(dbg, sr_uuid, vdi_uuid, description)

        def gen_uuid():
            return subprocess.Popen(["uuidgen", "-r"],
                                    stdout=subprocess.PIPE
                                    ).communicate()[0].strip()
        nil = xmlrpclib.dumps((None,), "", True, allow_none=True)
        if cmd == 'sr_create':
            SR().create(dbg, sr_uuid, dconf)
            print nil
        elif cmd == 'sr_delete':
            SR().destroy(dbg, sr_uuid)
            db_forget(vdi_uuid)
            print nil
        elif cmd == 'sr_scan':
            sr_ref = session.xenapi.SR.get_by_uuid(sr_uuid)
            vdis = session.xenapi.VDI.get_all_records_where(
                "field \"SR\" = \"%s\"" % sr_ref)
            xenapi_location_map = {}
            for vdi in vdis.keys():
                xenapi_location_map[vdis[vdi]['location']] = vdis[vdi]
            volumes = SR().ls(dbg, sr_uuid)
            volume_location_map = {}
            for volume in volumes:
                volume_location_map[volume['uri'][0]] = volume
            xenapi_locations = set(xenapi_location_map.keys())
            volume_locations = set(volume_location_map.keys())
            for new in volume_locations.difference(xenapi_locations):
                db_introduce(volume_location_map[new], gen_uuid())
            for gone in xenapi_locations.difference(volume_locations):
                db_forget(xenapi_location_map[gone]['uuid'])
            for existing in volume_locations.intersection(xenapi_locations):
                pass
            sr_update(sr_ref)
            print nil
        elif cmd == 'sr_attach':
            SR().attach(dbg, sr_uuid)
            print nil
        elif cmd == 'sr_detach':
            SR().detach(dbg, sr_uuid)
            print nil
        elif cmd == 'sr_update':
            sr_ref = session.xenapi.SR.get_by_uuid(sr_uuid)
            sr_update(sr_ref)
            print nil
        elif cmd == 'vdi_create':
            size = long(params['args'][0])
            if (size <= MIN_VDI_SIZE) or (size > MAX_VDI_SIZE):
                raise Exception("Invalid VDI size. "
                                "Size must be between 512 bytes and 16TiB")
            label = params['args'][1]
            description = params['args'][2]
            # read_only = params['args'][7] == "true"
            v = Volume().create(dbg, sr_uuid, label, description, size)
            uuid = gen_uuid()
            db_introduce(v, uuid)
            struct = {
                'location': v.uri,
                'uuid': uuid
            }
            print xmlrpclib.dumps((struct,), "", True)
        elif cmd == 'vdi_delete':
            Volume().destroy(dbg, sr_uuid, vdi_location)
            print nil
        elif cmd == 'vdi_clone':
            v = Volume().clone(dbg, sr_uuid, vdi_location)
            uuid = gen_uuid()
            db_introduce(v, uuid)
            struct = {
                'location': v.uri,
                'uuid': uuid
            }
            print xmlrpclib.dumps((struct,), "", True)
        elif cmd == 'vdi_snapshot':
            v = Volume().snapshot(dbg, sr_uuid, vdi_location)
            uuid = gen_uuid()
            db_introduce(v, uuid)
            struct = {
                'location': v.uri,
                'uuid': uuid
            }
            print xmlrpclib.dumps((struct,), "", True)
        elif cmd == 'vdi_attach':
            # writable = params['args'][0] == 'true'
            attach = Datapath().attach(dbg, vdi_location, 0)
            path = attach['implementation'][1]
            struct = {'params': path, 'xenstore_data': {}}
            print xmlrpclib.dumps((struct,), "", True)
        elif cmd in ('vdi_detach', 'vdi_detach_from_config'):
            Datapath().detach(dbg, vdi_location, 0)
            print nil
        elif cmd == 'vdi_activate':
            # writable = params['args'][0] == 'true'
            Datapath().activate(dbg, vdi_location, 0)
            print nil
        elif cmd == 'vdi_deactivate':
            Datapath().deactivate(dbg, vdi_location, 0)
            print nil
        elif cmd == 'vdi_resize':
            size = long(params['args'][0])
            Volume().resize(dbg, sr_uuid, vdi_uuid, size)
            sr_ref = session.xenapi.SR.get_by_uuid(sr_uuid)
            vdi_ref = session.xenapi.VDI.get_by_uuid(vdi_uuid)
            sr_update(sr_ref)
            session.xenapi.VDI.set_virtual_size(vdi_ref, str(size))
            session.xenapi.VDI.set_physical_utilisation(vdi_ref, str(size))
            struct = {'location': vdi_location,
                      'uuid': vdi_uuid}
            print xmlrpclib.dumps((struct,), "", True)
        elif cmd == 'vdi_update':
            vdi_update()
            print nil
        elif cmd in ['vdi_epoch_begin', 'vdi_epoch_end']:
            print nil
        else:
            fault = xmlrpclib.Fault(int(errno.EINVAL),
                                    "Unimplemented command: %s" % cmd,
                                    "",
                                    True)
            print xmlrpclib.dumps(fault)
    except Exception, e:
        info = sys.exc_info()
        if info[0] == exceptions.SystemExit:
            sys.exit(0)
        tb = "\n".join(traceback.format_tb(info[2]))
        fault = xmlrpclib.Fault(int(errno.EINVAL), str(e) + "\n" + tb)
        # errmsg = xmlrpclib.dumps(xmlrpclib.Fault(int(errno.EINVAL),
        #                          str(e)), "", True)
        error_xml = xmlrpclib.dumps(fault, "", True)
        print error_xml

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
         style SRs, while actually using SMAPIv1
"""

# pylint: disable=missing-docstring

import errno
import exceptions
import fcntl
import json
import sys
import syslog
import os
import traceback
import uuid
import xapi.storage.api.volume  # pylint: disable=import-error
import xmlrpclib
import XenAPI

STORE_PATH = "/var/run/smchim/"
MIN_VDI_SIZE = 512  # 512 bytes
MAX_VDI_SIZE = 16 * 1024 * 1024 * 1024 * 1024  # 16TB


def log(message):
    # LOG_LOCAL2 is written to /var/log/SMlog on XenServer
    syslog.openlog(sys.argv[0], syslog.LOG_PID, syslog.LOG_LOCAL2)
    syslog.syslog(str(message))
    syslog.closelog()


def _db_introduce_vdi(session, sr_uuid, volume, vdi_uuid):
    sm_config = {}
    volume_type = "user"
    is_a_snapshot = False
    metadata_of_pool = "OpaqueRef:NULL"
    snapshot_time = "19700101T00:00:00Z"
    snapshot_of = "OpaqueRef:NULL"
    shareable = True
    sr_ref = session.xenapi.SR.get_by_uuid(sr_uuid)
    read_only = False
    managed = True
    session.xenapi.VDI.db_introduce(vdi_uuid,
                                    volume['name'],
                                    volume['description'],
                                    sr_ref,
                                    volume_type,
                                    shareable,
                                    read_only,
                                    {},
                                    volume['uri'][0],
                                    {},
                                    sm_config,
                                    managed,
                                    str(volume['virtual_size']),
                                    str(volume['virtual_size']),
                                    metadata_of_pool,
                                    is_a_snapshot,
                                    xmlrpclib.DateTime(snapshot_time),
                                    snapshot_of)


def _db_forget_vdi(session, vdi_uuid):
    vdi = session.xenapi.VDI.get_by_uuid(vdi_uuid)
    session.xenapi.VDI.db_forget(vdi)


def _sr_update(session, dbg, sr_implementation, sr_uuid, sr_ref):
    sr_string = _read_from_store(sr_uuid, 'sr_string')
    # Get sr_implementation stats and update XAPI
    stats = sr_implementation().stat(dbg, sr_string)
    # Setting to 0 means that XAPI calculates virtual allocation itself
    session.xenapi.SR.set_virtual_allocation(
        sr_ref, str(0))
    session.xenapi.SR.set_physical_size(
        sr_ref, str(stats["total_space"]))
    session.xenapi.SR.set_physical_utilisation(
        sr_ref, str(stats["total_space"] - stats["free_space"]))
    # Update the on-disk name and description if needed
    name = session.xenapi.SR.get_name_label(sr_ref)
    if name != stats['name']:
        try:
            sr_implementation().set_name(dbg, sr_string, name)
        except (xapi.storage.api.volume.Unimplemented, AttributeError):
            # Not a problem, if not implemented
            pass
    description = session.xenapi.SR.get_name_description(sr_ref)
    if description != stats['description']:
        try:
            sr_implementation().set_description(dbg, sr_string, description)
        except (xapi.storage.api.volume.Unimplemented, AttributeError):
            # Not a problem, if not implemented
            pass


def sr_scan(dbg, session, sr_implementation, sr_uuid):
    sr_ref = session.xenapi.SR.get_by_uuid(sr_uuid)
    vdis = session.xenapi.VDI.get_all_records_where(
        "field \"SR\" = \"%s\"" % sr_ref)
    xenapi_location_map = {}
    for vdi in vdis.keys():
        xenapi_location_map[vdis[vdi]['location']] = vdis[vdi]
    sr_string = _read_from_store(sr_uuid, 'sr_string')
    volumes = sr_implementation().ls(dbg, sr_string)
    volume_location_map = {}
    for volume in volumes:
        # Workaround bug in ffs - spare slash
        # https://github.com/xapi-project/ffs/pull/61
        volume['uri'][0] = volume['uri'][0].replace("////", "///")
        volume_location_map[volume['uri'][0]] = volume
    xenapi_locations = set(xenapi_location_map.keys())
    volume_locations = set(volume_location_map.keys())
    store_update = {}
    for new in volume_locations.difference(xenapi_locations):
        vdi_uuid = get_or_make_uuid(volume_location_map[new])
        _db_introduce_vdi(session, sr_uuid, volume_location_map[new],
                          vdi_uuid)
        store_update[vdi_uuid] = volume_location_map[new]['key']
    for gone in xenapi_locations.difference(volume_locations):
        _db_forget_vdi(session, xenapi_location_map[gone]['uuid'])
        store_update[xenapi_location_map[gone]['uuid']] = None
    for existing in volume_locations.intersection(xenapi_locations):
        key = volume_location_map[existing]['key']
        store_update[xenapi_location_map[existing]['uuid']] = key
    _write_to_store(sr_uuid, store_update)
    _sr_update(session, dbg, sr_implementation, sr_uuid, sr_ref)


def _vdi_update(session, dbg, volume_implementation, sr_uuid, vdi_uuid):
    vdi_ref = session.xenapi.VDI.get_by_uuid(vdi_uuid)
    sr_string = _read_from_store(sr_uuid, 'sr_string')
    vdi_string = _read_from_store(sr_uuid, vdi_uuid)
    # Get volume stats and update XAPI
    stats = volume_implementation().stat(dbg, sr_string, vdi_string)
    if 'virtual_size' in stats:
        session.xenapi.VDI.set_virtual_size(vdi_ref,
                                            str(stats["virtual_size"]))
    if 'physical_utilisation' in stats:
        session.xenapi.VDI.set_physical_utilisation(
            vdi_ref, str(stats["physical_utilisation"]))
    # Update the on-disk name and description if needed
    name = session.xenapi.VDI.get_name_label(vdi_ref)
    if name != stats['name']:
        log("set_name")
        volume_implementation().set_name(dbg, sr_string, vdi_string, name)
    description = session.xenapi.VDI.get_name_description(vdi_ref)
    log("update")
    if description != stats['description']:
        log("set_description")
        volume_implementation().set_description(dbg, sr_string, vdi_string,
                                                description)


def get_or_make_uuid(volume):
    if volume['uuid']:
        return volume['uuid']
    else:
        return str(uuid.uuid4())


def _write_to_store(sr_uuid, update):
    try:
        os.makedirs(STORE_PATH)
    except OSError:
        # directory may exist already
        pass
    file_path = os.path.join(STORE_PATH, sr_uuid)
    with open(file_path, "a+") as file_pointer:
        fcntl.flock(file_pointer.fileno(), fcntl.LOCK_EX)
        file_pointer.seek(0)
        json_contents = file_pointer.read()
        if json_contents:
            contents = json.loads(json_contents)
        else:
            contents = {}
        for key, value in update.iteritems():
            if value:
                contents[key] = value
            elif key in contents:
                del contents[key]
        json_contents = json.dumps(contents)
        file_pointer.seek(0)
        file_pointer.truncate()
        file_pointer.write(json_contents)
        fcntl.flock(file_pointer.fileno(), fcntl.LOCK_UN)


class StoreKeyNotFound(BaseException):
    pass


def _read_from_store(sr_uuid, key):
    file_path = os.path.join(STORE_PATH, sr_uuid)
    with open(file_path) as file_pointer:
        fcntl.flock(file_pointer.fileno(), fcntl.LOCK_SH)
        contents = file_pointer.read()
        fcntl.flock(file_pointer.fileno(), fcntl.LOCK_UN)
    data = json.loads(contents)
    if key not in data:
        raise StoreKeyNotFound("Unknown key: %s" % (key))
    return data[key]


def _wipe_store(sr_uuid):
    file_path = os.path.join(STORE_PATH, sr_uuid)
    os.remove(file_path)


def main(plugin_implementation, sr_implementation, volume_implementation,
         datapath_implementation):
    log(sys.argv)

    try:
        dbg = "Dummy"

        params, cmd = xmlrpclib.loads(sys.argv[1])

        if cmd == 'sr_get_driver_info':
            results = {}
            query_result = plugin_implementation().query(dbg)
            for key in ['name', 'description', 'vendor', 'copyright']:
                results[key] = query_result[key]
            drivername = os.path.basename(sys.argv[0])
            if drivername[-2:] != 'SR':
                raise Exception('%s name needs to end with SR')
            drivername = drivername[:-2]
            results['name'] = drivername
            results['driver_version'] = query_result['version']
            results['capabilities'] = query_result['features']
            # SMAPIv1 uses VDI_DELETE instead of VDI_DESTROY
            if 'VDI_DESTROY' in results['capabilities']:
                results['capabilities'].remove('VDI_DESTROY')
                results['capabilities'].append('VDI_DELETE')
            results['required_api_version'] = '1.1'
            options = []
            for option in []:
                options.append({'key': option[0], 'description': option[1]})
            results['configuration'] = options
            print xmlrpclib.dumps((results,), "", True)
            sys.exit(0)

        params = params[0]
        session = XenAPI.xapi_local()
        ref = params['session_ref']
        session._session = ref  # pylint: disable=protected-access
        dconf = params['device_config']
        if 'sr_uuid' in params:
            sr_uuid = params['sr_uuid']
        if 'vdi_uuid' in params:
            vdi_uuid = params['vdi_uuid']
            try:
                vdi_string = _read_from_store(sr_uuid, vdi_uuid)
            except StoreKeyNotFound:
                # We can get here, if a VDI was created on a different host.
                # or if sr_scan was never run on this host.
                # Let's do an sr_scan to refresh the store and try again.
                sr_scan(dbg, session, sr_implementation, sr_uuid)
                vdi_string = _read_from_store(sr_uuid, vdi_uuid)
        if 'vdi_location' in params:
            vdi_location = params['vdi_location']

        nil = xmlrpclib.dumps((None,), "", True, allow_none=True)
        if cmd == 'sr_create':
            uri = dconf['uri']
            # ToDo: get these from xapi
            name = ''
            description = ''
            sr_implementation().create(dbg, uri, name, description, dconf)
            print nil
        elif cmd == 'sr_delete':
            sr_string = _read_from_store(sr_uuid, 'sr_string')
            sr_implementation().destroy(dbg, sr_string)
            # ToDo: should this be dropped or sr_uuid?
            _db_forget_vdi(session, vdi_uuid)
            print nil
        elif cmd == 'sr_scan':
            sr_scan(dbg, session, sr_implementation, sr_uuid)
            print nil
        elif cmd == 'sr_attach':
            uri = ''
            sr_string = sr_implementation().attach(dbg, dconf['uri'])
            _write_to_store(sr_uuid, {'sr_string': sr_string})
            print nil
        elif cmd == 'sr_detach':
            sr_string = _read_from_store(sr_uuid, 'sr_string')
            sr_implementation().detach(dbg, sr_string)
            _wipe_store(sr_uuid)
            print nil
        elif cmd == 'sr_update':
            sr_ref = session.xenapi.SR.get_by_uuid(sr_uuid)
            _sr_update(session, dbg, sr_implementation, sr_uuid, sr_ref)
            print nil
        elif cmd == 'vdi_create':
            size = long(params['args'][0])
            if (size <= MIN_VDI_SIZE) or (size > MAX_VDI_SIZE):
                raise Exception("Invalid VDI size. "
                                "Size must be between 512 bytes and 16TiB")
            name = params['args'][1]
            description = params['args'][2]
            # read_only = params['args'][7] == "true"
            sr_string = _read_from_store(sr_uuid, 'sr_string')
            volume = volume_implementation().create(dbg, sr_string, name,
                                                    description, size)
            vdi_uuid = get_or_make_uuid(volume)
            _db_introduce_vdi(session, sr_uuid, volume, vdi_uuid)
            struct = {
                'location': volume['uri'][0],
                'uuid': vdi_uuid
            }
            _write_to_store(sr_uuid, {vdi_uuid: volume['key']})
            print xmlrpclib.dumps((struct,), "", True)
        elif cmd == 'vdi_delete':
            sr_string = _read_from_store(sr_uuid, 'sr_string')
            volume_implementation().destroy(dbg, sr_string, vdi_string)
            print nil
        elif cmd == 'vdi_clone':
            sr_string = _read_from_store(sr_uuid, 'sr_string')
            volume = volume_implementation().clone(dbg, sr_string, vdi_string)
            vdi_uuid = get_or_make_uuid(volume)
            _db_introduce_vdi(session, sr_uuid, volume, vdi_uuid)
            struct = {
                'location': volume.uri,
                'uuid': vdi_uuid
            }
            print xmlrpclib.dumps((struct,), "", True)
        elif cmd == 'vdi_snapshot':
            sr_string = _read_from_store(sr_uuid, 'sr_string')
            volume = volume_implementation().snapshot(dbg, sr_string,
                                                      vdi_string)
            vdi_uuid = get_or_make_uuid(volume)
            _db_introduce_vdi(session, sr_uuid, volume, uuid)
            struct = {
                'location': volume.uri,
                'uuid': vdi_uuid
            }
            print xmlrpclib.dumps((struct,), "", True)
        elif cmd == 'vdi_attach':
            # writable = params['args'][0] == 'true'
            attach = datapath_implementation().attach(dbg, vdi_location, 0)
            path = attach['implementation'][1]
            struct = {'params': path, 'xenstore_data': {}}
            print xmlrpclib.dumps((struct,), "", True)
        elif cmd in ('vdi_detach', 'vdi_detach_from_config'):
            datapath_implementation().detach(dbg, vdi_location, 0)
            print nil
        elif cmd == 'vdi_activate':
            # writable = params['args'][0] == 'true'
            datapath_implementation().activate(dbg, vdi_location, 0)
            print nil
        elif cmd == 'vdi_deactivate':
            datapath_implementation().deactivate(dbg, vdi_location, 0)
            print nil
        elif cmd == 'vdi_resize':
            size = long(params['args'][0])
            sr_string = _read_from_store(sr_uuid, 'sr_string')
            volume_implementation().resize(dbg, sr_string, vdi_string, size)
            sr_ref = session.xenapi.SR.get_by_uuid(sr_uuid)
            vdi_ref = session.xenapi.VDI.get_by_uuid(vdi_uuid)
            _sr_update(session, dbg, sr_implementation, sr_uuid, sr_ref)
            session.xenapi.VDI.set_virtual_size(vdi_ref, str(size))
            session.xenapi.VDI.set_physical_utilisation(vdi_ref, str(size))
            struct = {'location': vdi_location,
                      'uuid': vdi_uuid}
            print xmlrpclib.dumps((struct,), "", True)
        elif cmd == 'vdi_update':
            _vdi_update(session, dbg, volume_implementation, sr_uuid, vdi_uuid)
            print nil
        elif cmd in ['vdi_epoch_begin', 'vdi_epoch_end']:
            print nil
        else:
            fault = xmlrpclib.Fault(int(errno.EINVAL),
                                    "Unimplemented command: %s" % cmd,
                                    "",
                                    True)
            print xmlrpclib.dumps(fault)
    except Exception as exception:
        info = sys.exc_info()
        if info[0] == exceptions.SystemExit:
            sys.exit(0)
        trace = "\n".join(traceback.format_tb(info[2]))
        fault = xmlrpclib.Fault(int(errno.EINVAL),
                                str(exception) + "\n" + trace)
        error_xml = xmlrpclib.dumps(fault, "", True)
        log(error_xml)
        print error_xml

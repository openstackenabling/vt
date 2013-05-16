#!/usr/bin/python
#
#    Copyright (C) 2013 Intel Corporation.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

#Tools to assign one VF to specified VM

import os
import nct
import xml.etree.ElementTree as ET

TMP_CONF_FILE = "/tmp/nct_vm_tmp.xml"

class NoDeviceAvailableError(Exception):
    def __init__(self):
        self.msg = "no VF available now"


class VTdNotSupportedError(Exception):
    def __init__(self):
        self.msg = "VT-d not supported by this host"


class DeviceFlag(object):
    def __init__(self):
        pass


class VTdProvider(object):
    def addVFToVM(self, vmName):
        nct.checkPermission()
        device = self.__getFreeDevice()
        #print "device available: %04x:%02x:%02x.%01x" % (device.domain,device.bus, device.slot, device.function)
        if device == None:
            raise NoDeviceAvailableError()
        self.__attachDevice(vmName, device.domain, device.bus, device.slot, device.function)

    def __attachDevice(self, vmName, domain, bus, slot, function):
        domainStr = "0x%04x" % domain
        busStr = "0x%02x" % bus
        slotStr = "0x%2x" % slot
        functionStr = "0x%1x" % function

        vmFile = '/etc/libvirt/qemu/%s.xml' % vmName
        tree = ET.parse(vmFile)
        doc = tree.getroot()
        for child in doc:
            if child.tag == "devices":
                #print 'add device now'
                hostdev = child.makeelement('hostdev', {'mode': 'subsystem', 'type': 'pci'})
                source = hostdev.makeelement('source', {})
                address = source.makeelement('address',
                    {'domain': domainStr, 'bus': busStr, 'slot': slotStr, 'function': functionStr})
                source.append(address)
                hostdev.append(source)
                child.append(hostdev)
                break

        f = open(TMP_CONF_FILE, "w")
        tree.write(f, "utf-8")
        f.close()

        cmd = 'virsh define %s' % TMP_CONF_FILE
        res = os.system(cmd)
        if res != 0:
            print "Failed to attach device"
        else:
            print "device attached successfully"


    def __getAllDevices(self):
        ndm = nct.NetworkDeviceManager()
        deviceList = ndm.devices
        flags = []
        for device in deviceList:
            if not device.isPhysical:
                device.showMe()
                flag = DeviceFlag()
                flag.domain = device.domain
                flag.bus = device.bus
                flag.slot = device.slot
                flag.function = device.func
                flag.used = False
                #print "get device: %04x:%02x:%02x.%01x" % (flag.domain,flag.bus, flag.slot, flag.function)
                flags = flags + [flag]
        return flags

    def __getFreeDevice(self):
        alldevices = self.__getAllDevices()
        vmFiles = os.listdir("/etc/libvirt/qemu")
        for vmFile in vmFiles:
            if vmFile.endswith(".xml") == False:
                #print "skipping " + vmFile
                continue

            realPath = "/etc/libvirt/qemu/%s" % vmFile
            tree = ET.parse(realPath)
            doc = tree.getroot()
            devices = doc.find("devices")
            if devices == None:
                continue

            hostdev = devices.find("hostdev")
            if hostdev == None:
                continue

            if hostdev.get("mode") != "subsystem":
                continue

            if hostdev.get("type") != "pci":
                continue

            address = hostdev.find("source").find("address")
            domain = int(address.get('domain'), 16)
            bus = int(address.get('bus'), 16)
            slot = int(address.get('slot'), 16)
            function = int(address.get('function'), 16)
            if bus == None or slot == None or function == None:
                continue

            print "attached vm: %s" % vmFile
            print "attached device: %04x:%02x:%02x.%01x" % (domain, bus, slot, function)

            for device in alldevices:
                print "comparing: %2x:%2x.%1x" % (device.bus, device.slot, device.function)
                if device.domain == domain and device.bus == bus and device.slot == slot and device.function == function:
                    print "device occupied: %04x:%02x:%02x.%01x" % (
                        device.domain, device.bus, device.slot, device.function)
                    device.used = True
                    break

        for device in alldevices:
            if not device.used:
                return device

if __name__ == "__main__":
    provider = VTdProvider()
    provider.addVFToVM("instance-00000034")

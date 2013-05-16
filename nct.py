#!/usr/bin/env python
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
"""
Driver ixgbe
=============

Driver ixgbe is used for following adapters:

- 82599-BASED ADAPTERS
- 82598-BASED ADAPTERS

max_vfs
-------
Valid Range:   0-63
Default Value: 0


Driver igb
=============

This driver supports all 82575, 82576 and 82580-based Intel (R) gigabit network
connections.

- 82575-BASED ADAPTERS
- 82576-BASED ADAPTERS
- 82580-BASED ADAPTERS

max_vfs
-------
Valid Range:   0-7
Default Value: 0
"""

import vmm
import os
import re

import fileinput

IOV_Devices = ['825785', '82576', '82580', '82598', '82599']

# Warning:
# This variable represents the file to modify to support IOmmu in kernel
# If it was modified incorrectly, the system may be not bootable, so highly
# suggest to modify it manually, not by the program.
# If you really need to use it in scripts, uncomment following line and remove 
# the line of "g.conf"
#KERNEL_BOOT_CONFIG_PATH = "/boot/grub/grub.conf"
KERNEL_BOOT_CONFIG_PATH = "g.conf"
SYSFS_NET_PATH = "/sys/class/net"
SYSFS_PCI_DEVICE_PATH = '/sys/class/pci_bus/%04x:%02x/device/%04x:%02x:%02x.%01x'
ARG_VERBOSE = False
SILENT_ON_ERROR = False


class VFNode(object):
    def __init__(self, name, id, alias, index):
        self.__name__ = name
        self.__id__ = id
        self.__alias__ = alias
        self.__index__ = index

    def name(self):
        return __name__

    def id(self):
        return self.__id__

    def alias(self):
        return self.__alias__

    def index(self):
        return self.__index__

    def showMe(self):
        print '\t vf: { %s, %s, %s, %d }' % (self.__id__, self.__name__, self.__alias__, self.__index__)

    name = property(name)
    id = property(id)
    alias = property(alias)
    index = property(index)


class PermissionDeniedError(Exception):
    def __init__(self):
        self.msg = "root previledge needed"


class InvalidPciDeviceIdError(Exception):
    def __init__(self, id):
        self.id = id
        self.msg = "invalid pci device id: %s" % id


class InvalidRequestError(Exception):
    def __init__(self, msg):
        self.msg = 'Invalid request: %s' % msg


class PciDeviceNotFoundError(Exception):
    def __init__(self, domain, bus, slot, func):
        self.domain = domain
        self.bus = bus
        self.slot = slot
        self.func = func
        self.name = "%04x:%02x:%02x.%01x" % (domain, bus, slot, func)

    def __str__(self):
        return ('PCI Device %s Not Found' % (self.name))


def checkPermission():
    if os.geteuid() != 0:
        raise PermissionDeniedError()


def showUsage():
    print "Usage: ./nct [COMMAND]"
    print "nct help to find and configure net cards supporting IOV"
    print ""
    print "Examples:"
    print "  nct list\t\t# List all network devices"
    print "  nct show eth2 \t# Show detail information about device"
    print "  nct attach eth2 vm1\t# Attach device eth2 to vm1"

#
# classs NetworkInterface represents one network interface visible to the system,
# which can be listed by 'ifconfig -a'
#
# To find out the relation between network interface and pci ethernet device,
# check /sys/bus/pci/devices/[pci device id]/net
#
# Note:
#   not all pci ethernet devices have related network interface, if the device
#   were detached, it doesn't have one network interface.
#
#
class NetworkInterface(object):
    def __init__(self, name):
        self.interface = ""

    def getName(self):
        return self.__name__

    def getIP(self):
        return self.__ip__

    def getNetMask(self):
        return self.__netmask__

    def getGateway(self):
        return self.__gateway__

    def getDNS(self):
        return self.__dns__

    def showMe(self):
        if self.interface != None:
            print "interface"

#
# class PCIEthernetDevice represents one pci ether device, which may be physical(PF)
# or virtual(VF). If it's PF, property 'supportVT' indicates whether it support
# IOMMU.
#
class PCIEthernetDevice(object):
    def pciDevicePath(self):
        return SYSFS_PCI_DEVICE_PATH % (
            self.__domain__, self.__bus__, self.__domain__, self.__bus__, self.__slot__, self.__func__)

    def __init__(self, numId):
        if ARG_VERBOSE:
            print "create PCI device with id: %s" % numId

        p = re.compile(r'\W+')
        nums = p.split(numId)

        if len(nums) < 3 or len(nums) > 4:
            raise InvalidPciDeviceIdError(numId)

        #TODO check numId format here
        if len(nums) == 3:
            self.__domain__ = 0
            self.__bus__ = int(nums[0], 16)
            self.__slot__ = int(nums[1], 16)
            self.__func__ = int(nums[2], 16)

        elif len(nums) == 4:
            self.__domain__ = int(nums[0], 16)
            self.__bus__ = int(nums[1], 16)
            self.__slot__ = int(nums[2], 16)
            self.__func__ = int(nums[3], 16)

        self.__id__ = "%04x:%02x:%02x.%01x" % (self.__domain__, self.__bus__, self.__slot__, self.__func__)
        if ARG_VERBOSE:
            print "device id: %s" % self.__id__

        self.refresh()

    def __initByDescription__(self):
        description = os.popen("lspci -s %s" % self.__id__).read()
        if ' 82599EB ' in description:
            self.__pf__ = True
            self.__supportVT__ = True
            self.__maxVFNumber__ = 63
        elif ' 82599 ' in description:
            self.__pf__ = False

    #
    # reload device information from system.
    #
    def refresh(self):
        self.__driver__ = None
        self.__module__ = None
        self.__pf__ = True
        self.__supportVT__ = False
        self.__maxVFNumber__ = 0
        self.__currentVFNumber__ = 0
        self.__vfs__ = []
        self.__nic__ = None

        self.__initByDescription__()

        # run 'lspci -s <id> -v' to get device information
        outputStr = os.popen("lspci -s %s -vv" % self.__id__).read()
        if 'Invalid slot number' in outputStr:
            raise PciDeviceNotFoundError(self.__domain__, self.__bus__, self.__slot__, self.__func__)

        lines = outputStr.splitlines()
        for line in lines:
            #print line

            if 'Kernel driver' in line:
                t1 = line.split(':')
                self.__driver__ = t1[1].strip()

            if 'Kernel modules' in line:
                t1 = line.split(':')
                self.__module__ = t1[1].strip()

            if 'Memory at' in line:
                if '[virtual]' in line:
                    self.__pf__ = False
                else:
                    self.__pf__ = True

            # in capabilities, we may see SR-IOV support
            # for example:
            #   Capabilities: [160] Single Root I/O Virtualization (SR-IOV)
            if '(SR-IOV)' in line:
                self.__supportVT__ = True

            # if SR-IOV is supported, we may see its capabilities here
            # for example:
            #   Initial VFs: 64, Total VFs: 64, Number of VFs: 2, Function Dependency Link: 00
            if 'Initial VFs:' in line:
                t1 = line.split(',')
                for prop in t1:
                    t2 = prop.split(':')
                    if 'TotalInitial VFs' in t2[0]:
                        self.__maxVFNumber__ = int(t2[1].strip())
                    if 'Initial VFsNumber of VFs' in t2[0]:
                        self.__currentVFNumber__ = int(t2[1].strip())

            # list virtual devices belong to this physical device
            if self.__pf__:
                self.__vfs__ = []
                names = os.listdir(self.pciDevicePath())
                for name in names:
                    if name.startswith('virtfn'):
                        if ARG_VERBOSE:
                            print "got virtual function: " + name
                        realChildPath = os.readlink(self.pciDevicePath() + '/' + name)
                        t1 = realChildPath.rsplit('/', 1)
                        vf = VFNode(name, t1[1], 'vf%s' % name[6:], int(name[6:]))
                        self.__vfs__ = self.__vfs__ + [vf]

                if self.__vfs__ != None:
                    if ARG_VERBOSE:
                        print "---- children ----"
                        print self.__vfs__

            # read net interface information for the device
            try:
                names = os.listdir(self.pciDevicePath() + '/net')
                if ARG_VERBOSE:
                    print "NID: " + names[0]
                self.__nic__ = NetworkInterface(names[0])
            except OSError, (errno, errMsg):
                pass
                #print errMsg
                # in this case, the driver is not ready, or the device has been detached

    # ==== basic device information ====
    def getId(self):
        return self.__id__

    def getName(self):
        return self.__name__

    def getDomain(self):
        return self.__domain__

    def getBus(self):
        return self.__bus__

    def getSlot(self):
        return self.__slot__

    def getFunc(self):
        return self.__func__

    # ===== driver and modules ====
    def getDriverName(self):
        return self.__driver__

    def getKernelModule(self):
        return self.__module__

    # ==== VT information ====
    def isPysical(self):
        return self.__pf__

    def supportVT(self):
        return self.__supportVT__

    def getMaxVFNumber(self):
        return self.__maxVFNumber__

    def currenVFNumber(self):
        return self.__currentVFNumber__

    def rateLimit(self):
        return self.__rateLimit__

    def setRateLimit(self, limit):
        self.__rateLimit__ = limit

    def vfs(self):
        return self.__vfs__

    def getNetworkInterface(self):
        return self.__nic__

    # ==== attach/detach ====
    def detached(self):
        return 'stub' in self.__driver__

    def detach(self):
        if self.detached():
            return True

        # TODO check status, if already detached, ignore this request
        outputStr = os.popen("virsh nodedev-dettach pci_%04x_%02x_%02x_%01x"
                             % (self.__domain__, self.__bus__, self.__slot__, self.__func__)).read()
        if 'dettached' in outputStr:
            self.__nic__ = None
            self.__driver__ = 'pci-stub'

    def attach(self):
        if self.detached() != True:
            return True

        # TODO check status, if already detached, ignore this request
        outputStr = os.popen("virsh nodedev-reattach pci_%04x_%02x_%02x_%01x"
                             % (self.__domain__, self.__bus__, self.__slot__, self.__func__)).read()
        if 'dettached' in outputStr:
            self.__nic__ = None
            self.__driver__ = 'pci-stub'
            # TODO: notify with device change
            self.refresh()


    def reconfig(self, vfNumber, force):
        # if some VFs have been attached to VM,
        if self.__driver__ == None:
            raise InvalidRequestError('driver not ready')
        if self.__pf__ != True:
            raise InvalidRequestError('operation not supported on virtual device')
        if self.__supportVT__ != True:
            raise InvalidRequestError('operation not support on this device')
        if vfNumber > self.__maxVFNumber__:
            raise InvalidRequestError('vf number exceeds driver not ready')

        res = os.system('modprobe -r %s' % self.__driver__)
        if res != 0:
            return res

        res = os.system('modprobe %s max_vfs=%d' % (self.__driver__, vfNumber))
        if res != 0:
            if SILENT_ON_ERROR == False:
                print "Error: failed to enable driver with iommu support"
            return res

        return 0


    def showMe(self):
        print '========== device info ========='
        print 'id: \t\t%s' % self.__id__
        print 'driver: \t%s' % self.__driver__
        print 'module: \t%s' % self.__module__
        print 'pf: \t\t%s' % self.__pf__
        print 'supportVT: \t%s' % self.__supportVT__
        print 'maxVFNumber: \t%s' % self.__maxVFNumber__
        print 'currentVFNumber: \t%s' % self.__currentVFNumber__
        if self.__vfs__ != None:
            for vf in self.__vfs__:
                vf.showMe()

        if self.__nic__ != None:
            self.__nic__.showMe()
        print '========== device info done ========='


    id = property(getId)
    name = property(getName)
    domain = property(getDomain)
    bus = property(getBus)
    slot = property(getSlot)
    func = property(getFunc)
    driver = property(getDriverName)
    module = property(getKernelModule)
    isPhysical = property(isPysical)
    supportVT = property(supportVT)
    maxVFNumber = property(getMaxVFNumber)
    currenVFNumber = property(currenVFNumber)
    rateLimit = property(rateLimit)
    vfs = property(vfs)
    nic = property(getNetworkInterface)


# List all physical/virtual ethernet devices available in pci bus
def listDevices():
    checkPermission()

    outputStr = os.popen("lspci | grep Ethernet").read().splitlines()

    for line in outputStr:
        t1 = line.split(' ')
        yield PCIEthernetDevice(t1[0])


class NetworkDeviceManager(object):
    def __init__(self):
        self.refresh()

    def refresh(self):
        self.__devices__ = []

        # list all ethernet devices
        self.__devices__ = []
        outputStr = os.popen("lspci | grep Ethernet").read().splitlines()
        for line in outputStr:
            t1 = line.split(' ')
            dev = PCIEthernetDevice(t1[0])
            self.__devices__ = self.__devices__ + [dev]


    def addToVM(self, device, vm):
        # if the device has been attached, fail
        # if the vm has been started, warn
        # 
        vmm.addDevice(device.__domain__, device.__bus__, device.__slot__, device.__func__, vm)

    def removeFromVM(self, device, vm):
        vmm.reoveDevice(device.__domain__, device.__bus__, device.__slot__, device.__func__, vm)

    def setMacAddr(self, devId, mac):
        device = self.getDevice(devId)
        if device == None:
            raise InvalidPciDeviceIdError(devId)

        if device.isPhysical:
            raise InvalidRequestError('setting mac only applies to virtual functions')

        parentDevice = self.getPhysicalDevice(devId)
        if parentDevice == None:
            raise InvalidPciDeviceIdError('physical device not found')

        vfNode = self.getVFNodegetAlias(devId)
        cmd = 'ip link set %s vf %d mac %s' % (parentDevice.nic.name, vfNode.index, mac)
        err = os.system(cmd)
        if err != 0:
            print 'Failed to change mac address'
            return False

        return True


    def getDevices(self):
        return self.__devices__

    def getDevice(self, deviceId):
        for device in self.__devices__:
            if device.id == deviceId:
                return device

        return None

    def getPhysicalDevice(self, vfdeviceId):
        for device in self.__devices__:
            if device.vfs != None:
                for vf in device.vfs:
                    if vf.id == vfdeviceId:
                        return device

        return None

    def getVFNode(self, vfdeviceId):
        for device in self.__devices__:
            if device.vfs != None:
                for vf in device.vfs:
                    if vf.id == vfdeviceId:
                        return vf

        return None

        # virtualize PFs with specified driver to specified vf number

        # Note:

    #   the module for the PF will be reloaded, so all devices depend on the module
    #   will be down.
    #   Take it carefully especially you are doing this remotely, the remote channel
    #   may be disconnected if it also use the module.
    #
    def virtualize(self, driver, vfNumber):
        cmd = 'modprobe -r %s' % driver
        print "running: %s" % cmd
        res = os.system(cmd)
        if res != 0:
            return res

        cmd = 'modprobe %s max_vfs=%d' % (driver, vfNumber)
        print "running: %s" % cmd
        res = os.system(cmd)
        if res != 0:
            if SILENT_ON_ERROR == False:
                print "Error: failed to enable driver with iommu support"
            return res

        self.refresh()
        return 0

    def getDevices(self):
        return self.__devices__

    devices = property(getDevices)

# If you are in doubt whether your motherboard or CPU supports VT-d or not,
# the Xen VT-d wikipage has some pointers of VT-d enabled chipsets, motherboards
# and CPUs: http://wiki.xensource.com/xenwiki/VTdHowTo

def checkServerIOmmu():
    # check cpu/board/kernel support
    outputStr = os.popen("dmesg | grep -e DMAR -e IOMMU").read()
    #print outputStr

    if 'DMAR' in outputStr and 'IOMMU' in outputStr:
        return True
    else:
        return False


def checkKernelIOmmu():
    outputStr = os.popen('grep intel_iommu=on %s' % KERNEL_BOOT_CONFIG_PATH).read()
    if 'iommu' in outputStr:
        return True
    else:
        return False


def checkIOmmu():
    if checkKernelIOmmu == False:
        return False

    return checkServerIOmmu()

#
# Enable IOMMU support in kernel boot arguments
# 
# This function will modify kernel boot file, be careful do this, if unexpected
# error occurs, the system may be corrupted.
#
# If return True, kernel has been successfully configured to enaable IOmmu, but
# only take effect after reboot.
#
def enableKernelIOmmu():
    checkPermission()

    try:
        new_lines = []
        for line in fileinput.input(KERNEL_BOOT_CONFIG_PATH):
            strip_line = line.strip()
            if strip_line.startswith('kernel'):
                if 'intel_iommu=on' in line:
                    print "already enabled"
                    return True
                elif 'intel_iommu=off' in line:
                    print "enabling now"
                    line = line.replace('intel_iommu=off', 'intel_iommu=on')
                else:
                    line = line + ' intel_iommu=on'

            new_lines = new_lines + [line]

        if ARG_VERBOSE:
            print new_lines

        file = open(KERNEL_BOOT_CONFIG_PATH, 'w')
        file.writelines(new_lines)
        file.close()
        return True

    except OSError, (errno, errMsg):
        return False

#
# Disable IOMMU support in kernel boot arguments
# 
# This function will modify kernel boot file, be careful do this, if unexpected
# error occurs, the system may be corrupted.
#
# If return True, kernel has been successfully configured to disable IOmmu, but
# only take effect after reboot.
#
def disableKernelIOmmu():
    checkPermission()

    try:
        new_lines = []
        for line in fileinput.input(KERNEL_BOOT_CONFIG_PATH):
            strip_line = line.strip()
            if strip_line.startswith('kernel'):
                if 'intel_iommu=off' in line:
                    print "already disabled"
                    return True
                elif 'intel_iommu=on' in line:
                    print "disabling now"
                    line = line.replace('intel_iommu=on', 'intel_iommu=off')
                else:
                    line = line + ' intel_iommu=off'

            new_lines = new_lines + [line]

        file = open(KERNEL_BOOT_CONFIG_PATH, 'w')
        file.writelines(new_lines)
        file.close()
        return True

    except OSError, (errno, errMsg):
        # error 1: file not found
        # error 2: no permission
        return False


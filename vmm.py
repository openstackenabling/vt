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

class vm(object):
    def __init__(self, name):
        self.name = name


class vmm(object):
    """
    Provides an interface for VMM operations.
    """

    def addDevice(self, domain, bus, slot, func, vm):
        raise NotImplementedError

    def removeDevice(self, domain, bus, slot, func, vm):
        raise NotImplementedError

    def getAttachedVM(self, domain, bus, slot, func):
        raise NotImplementedError

    def isDeviceAttached(self, domain, bus, slot, func):
        raise NotImplementedError

    def isStarted(self, vm):
        """
        whether specified vm is running
        """
        raise NotImplementedError
    
    
  


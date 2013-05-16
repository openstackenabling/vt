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
Network intensive Scheduler
"""

from nova import flags
from nova.openstack.common import cfg
from nova.scheduler import driver
from nova import log as logging
from nova.scheduler.simple import SimpleScheduler

LOG = logging.getLogger(__name__)

network_intensive_scheduler_opts = [
    cfg.IntOpt("network_intensive_flavorid",
        default=0,
        help="The flavor id for network intensive flavor type"),
    cfg.StrOpt('network_intensive_host',
        default='',
        help='The compute host that has network intensive capability'),
]

FLAGS = flags.FLAGS
FLAGS.register_opts(network_intensive_scheduler_opts)

class NetworkIntensiveScheduler(SimpleScheduler):
    """
    We define a flavor type: network intensive VM,
    for those kind of vms that need intensive network, we will schedule it to the compute hosts that have network-intensive
    capability configured.

    Now, for demo:
    We just hard code the schedule algorithm, in the future, we will refactor it.
    """

    def schedule_run_instance(self, context, request_spec, *_args, **_kwargs):
        """
        Override simple scheduler to provide our scheduler algorithm
        """
        LOG.info("configuration info:network flavorid: '%(flavorid)s' and host:'%(host)s'" % {
            'flavorid': FLAGS.network_intensive_flavorid, 'host': FLAGS.network_intensive_host})
        num_instances = request_spec.get('num_instances', 1)
        instances = []
        for num in xrange(num_instances):
            flavorId = request_spec['instance_type']['flavorid']
            flavorName = request_spec['instance_type']['name']
            LOG.info("flavorid is: '%(flavorId)s' and name is: '%(flavorName)s'" % locals())
            if int(flavorId) == FLAGS.network_intensive_flavorid:
                host = FLAGS.network_intensive_host
            else:
                host = self._schedule_instance(context, request_spec['instance_properties'], *_args, **_kwargs)

            LOG.info("schedule to host: '%(host)s'" % locals())
            request_spec['instance_properties']['launch_index'] = num
            instance_ref = self.create_instance_db_entry(context, request_spec)
            driver.cast_to_compute_host(context, host, 'run_instance', instance_uuid=instance_ref['uuid'], **_kwargs)
            instances.append(driver.encode_instance(instance_ref))
            # So if we loop around, create_instance_db_entry will actually
            # create a new entry, instead of assume it's been created
            # already
            del request_spec['instance_properties']['uuid']
        return instances




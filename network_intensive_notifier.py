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

from nova import log as logging, utils
from vtp import VTdProvider
from nova import flags
import nova.context

FLAGS = flags.FLAGS
LOG = logging.getLogger(__name__)

def notify(message):
    """When the event type is compute.instance.create.end,
    then invoke the script to set the network information
    """
    LOG.info(message)
    event_type = message['event_type']
    if event_type == "compute.instance.create.end":
        LOG.info("Creating the instance ended")
        provider = VTdProvider()
        instance_id = message['payload']['instance_id']
        db_driver = FLAGS.db_driver
        db = utils.import_object(db_driver)
        context = nova.context.get_admin_context()
        instance = db.instance_get_by_uuid(context, instance_id)
        instance_name = instance['name']
        LOG.info("instance id is: '%(instance_id)s' and name is: '%(instance_name)s'" % locals())
        provider.addVFToVM(instance_name)


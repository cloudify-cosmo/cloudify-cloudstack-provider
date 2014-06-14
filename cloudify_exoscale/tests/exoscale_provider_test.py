########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
############

__author__ = 'adaml'

import unittest
import os
from cloudify_exoscale.cloudify_exoscale import _read_config
from cloudify_exoscale.cloudify_exoscale import ExoscaleLogicError
from cloudify_exoscale.cloudify_exoscale import ExoscaleConnector
from cloudify_exoscale.cloudify_exoscale import ExoscaleKeypairCreator
from cloudify_exoscale.cloudify_exoscale import \
    ExoscaleSecurityGroupCreator
import logging


class ExoscaleProviderTestCase(unittest.TestCase):
    lgr = logging.getLogger('unittest')

    def test_provider_init(self):
        """
        Check initialization validity.
        """
        # is_init_valid = init(__file__, True)
        # if not is_init_valid:
        # raise AssertionError("Failed initializing Exoscale Provider.")

    def test_create_keypairs(self):
        """
        Tests create agent and management keypairs, passing private key target
        path
        """
        mgmt_key_name = "temp-unittest-mgmt-key"
        agent_key_name = "temp-unittest-agent-key"

        provider_config = _read_config(None)

        # setting special unit-test keynames.
        provider_config['compute']['management_server'][
            'management_keypair']['name'] = mgmt_key_name
        provider_config['compute']['agent_servers'][
            'agents_keypair']['name'] = agent_key_name

        cloud_driver = ExoscaleConnector(provider_config).create()

        keypair_creator = ExoscaleKeypairCreator(cloud_driver, provider_config)

        try:
            mgmt_pk_target_path = os.path.join(os.path.dirname(
                os.path.realpath(__file__)), mgmt_key_name + ".pem")
            agent_pk_target_path = os.path.join(os.path.dirname(
                os.path.realpath(__file__)), agent_key_name + ".pem")
            keypair_creator.create_key_pairs(
                mgmt_private_key_target_path=mgmt_pk_target_path,
                mgmt_keypair_name=mgmt_key_name,
                agent_private_key_target_path=agent_pk_target_path,
                agent_keypair_name=agent_key_name)

            if not keypair_creator._get_keypair(mgmt_key_name):
                raise AssertionError('management keypair not created.')
            if not keypair_creator._get_keypair(agent_key_name):
                raise AssertionError('agent keypair not created.')

            keypair_creator.delete_keypairs()

            if keypair_creator._get_keypair(mgmt_key_name):
                raise AssertionError('management keypair was not deleted.')
            if keypair_creator._get_keypair(agent_key_name):
                raise AssertionError('agent keypair was not deleted.')

        finally:
            try:
                cloud_driver.ex_delete_keypair(mgmt_key_name)
                cloud_driver.ex_delete_keypair(agent_key_name)
            except:
                pass

    def test_keypair_import(self):
        """
        Tests public key import, passing public key path
        """
        resource_folder_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "test_resources")

        provider_config = _read_config(None)

        mgmt_key_name = 'temp-unittest-management-key'
        agent_key_name = 'temp-unittest-agent-key'

        # setting special unit-test keynames.
        provider_config['compute']['management_server'][
            'management_keypair']['name'] = mgmt_key_name
        provider_config['compute']['agent_servers'][
            'agents_keypair']['name'] = agent_key_name

        public_key_name = 'public_key.pub'
        public_key_path = os.path.join(resource_folder_path, public_key_name)
        try:
            cloud_driver = ExoscaleConnector(provider_config).create()

            keypair_creator = ExoscaleKeypairCreator(cloud_driver,
                                                     provider_config)

            keypair_creator.create_key_pairs(
                mgmt_public_key_filepath=public_key_path,
                mgmt_keypair_name=mgmt_key_name,
                agent_public_key_filepath=public_key_path,
                agent_keypair_name=agent_key_name)

            keypair_creator.delete_keypairs()

            if keypair_creator._get_keypair(mgmt_key_name):
                raise AssertionError('management keypair was not deleted.')
            if keypair_creator._get_keypair(agent_key_name):
                raise AssertionError('agent keypair was not deleted.')

        finally:
            try:
                cloud_driver.ex_delete_keypair(mgmt_key_name)
                cloud_driver.ex_delete_keypair(agent_key_name)
            except:
                pass

    def test_get_keypair(self):

        key_name = "temp_unittest_key"

        provider_config = _read_config(None)

        cloud_driver = ExoscaleConnector(provider_config).create()

        keypair_creator = ExoscaleKeypairCreator(cloud_driver, provider_config)
        key_pair = keypair_creator._get_keypair(key_name)
        if key_pair:
            raise AssertionError(
                'the keypair {0} should not exist'.format(key_name))
        cloud_driver.ex_create_keypair(key_name)
        key_pair = keypair_creator._get_keypair(key_name)
        if not key_pair:
            raise AssertionError(
                'expecting to find an existing keypair with name {0}'.format(
                    key_name))

        cloud_driver.ex_delete_keypair(key_name)

    def test_create_security_group(self):
        """
        Tests create security group.
        """
        management_security_group_name = 'temp_unittest-mngt-sg'
        agent_security_group_name = 'temp_unittest-agent-sg'
        provider_config = _read_config(None)

        # change security-group name so test will not affect production
        provider_config['networking']['management_security_group'][
            'name'] = management_security_group_name
        provider_config['networking']['agents_security_group'][
            'name'] = agent_security_group_name

        self.cloud_driver = ExoscaleConnector(provider_config).create()

        try:
            sg_creator = ExoscaleSecurityGroupCreator(self.cloud_driver,
                                                      provider_config)
            sg_creator.create_security_groups()

            if sg_creator.get_security_group(
                    management_security_group_name) is None:
                raise AssertionError(
                    'expecting to find security group {0}'.format(
                        management_security_group_name))
            if sg_creator.get_security_group(
                    agent_security_group_name) is None:
                raise AssertionError(
                    'expecting to find security group {0}'.format(
                        agent_security_group_name))

            sg_creator.delete_security_groups()

            if sg_creator.get_security_group(
                    management_security_group_name):
                raise AssertionError(
                    'expecting security group {0} to be deleted'.format(
                        management_security_group_name))
            if sg_creator.get_security_group(agent_security_group_name):
                raise AssertionError(
                    'expecting security group {0} to be deleted'.format(
                        agent_security_group_name))
        finally:
            try:
                self.cloud_driver.ex_delete_security_group(
                    management_security_group_name)
            except:
                pass

            try:
                self.cloud_driver.ex_delete_security_group(
                    agent_security_group_name)
            except:
                pass

    def test_use_existing_security_group_not_found(self):
        """
        Tests create security group with 'use_existing' property set to true
        """
        provider_config = _read_config(None)

        # security-group use_existing=True
        provider_config['networking']['management_security_group'][
            'use_existing'] = True
        provider_config['networking']['management_security_group'][
            'name'] = 'non-existing-sg'

        cloud_driver = ExoscaleConnector(provider_config).create()
        sg_creator = ExoscaleSecurityGroupCreator(
            cloud_driver, provider_config)
        try:
            sg_creator.create_security_groups()
            raise AssertionError(
                'Security-group validation failed. Non existing group did not '
                'raise an error as expected')
        except ExoscaleLogicError:
            pass

    def test_security_group_does_not_exist(self):
        """
        Tests create security group with use_existing=True expecting an error
        """
        existing_sg_name = 'temp-unittest-security-group'
        provider_config = _read_config(None)

        provider_config['networking']['management_security_group'][
            'use_existing'] = True
        provider_config['networking']['management_security_group'][
            'name'] = existing_sg_name

        cloud_driver = ExoscaleConnector(provider_config).create()
        sg_creator = ExoscaleSecurityGroupCreator(cloud_driver,
                                                  provider_config)
        try:
            sg_creator.create_security_groups()
            raise AssertionError(
                'Security-group validation failed. '
                'use_existing flag did not '
                'raise an error as expected')
        except ExoscaleLogicError:
            pass

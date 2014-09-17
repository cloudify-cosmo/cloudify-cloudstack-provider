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

__author__ = 'rkuipers'
import os
import shutil

from copy import deepcopy
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
import yaml
import errno
import time

from fabric.api import put, env
from fabric.context_managers import settings

import libcloud.security
# from CLI
# provides a logger to be used throughout the provider code
# returns a tuple of a main (file+console logger) and a file
# (file only) logger.
from cosmo_cli.cosmo_cli import init_logger
# from cosmo_cli.cosmo_cli import set_global_verbosity_level
# provides 2 base methods to be used.
# if not imported, the bootstrap method must be implemented
from cosmo_cli.provider_common import BaseProviderClass
from os.path import expanduser

libcloud.security.VERIFY_SSL_CERT = False

# initialize logger
lgr, flgr = init_logger()

CONFIG_FILE_NAME = 'cloudify-config.yaml'
DEFAULTS_CONFIG_FILE_NAME = 'cloudify-config.defaults.yaml'


is_verbose_output = False


class ProviderManager(BaseProviderClass):

    """class for base methods
        name must be kept as is.

        inherits BaseProviderClass from the cli containing the following
        methods:
        __init__: initializes base mandatory params provider_config and
        is_verbose_output. additionally, optionally receives a schema param
        that enables the default schema validation method to be executed.
        bootstrap: installs cloudify on the management server.
        validate_config_schema: validates a schema file against the provider
        configuration file supplied with the provider module.
        (for more info on BaseProviderClass, see the CLI's documentation.)

        ProviderManager classes:
        __init__: *optional* - only if more params are initialized
        provision: *mandatory*
        validate: *mandatory*
        teardown: *mandatory*
        """

    def __init__(self, provider_config=None, is_verbose_output=False):
        """
        initializes base params.
        provider_config and is_verbose_output are initialized in the
        base class and are mandatory. if more params are needed, super can
        be used to init provider_config and is_verbose_output.

        :param dict provider_config: inherits the config yaml from the cli
        :param bool is_verbose_output: self explanatory
        :param dict schema: is an optional parameter containing a jsonschema
        object. If initialized it will automatically trigger schema validation
        for the provider.
        """
        self.provider_config = provider_config
        super(ProviderManager, self).__init__(provider_config,
                                              is_verbose_output)

    def _get_private_key_path_from_keypair_config(self, keypair_config):
        path = keypair_config['provided']['private_key_filepath'] if \
            'provided' in keypair_config else \
            keypair_config['auto_generated']['private_key_target_path']
        return expanduser(path)

    def copy_files_to_manager(self, mgmt_ip, config, ssh_key, ssh_user):
        def _copy(userhome_on_management, agents_key_path):

            env.user = ssh_user
            env.key_filename = ssh_key
            env.abort_on_prompts = False
            env.connection_attempts = 12
            env.keepalive = 0
            env.linewise = False
            env.pool_size = 0
            env.skip_bad_hosts = False
            env.timeout = 5
            env.forward_agent = True
            env.status = False
            env.disable_known_hosts = False

            lgr.info('uploading agents private key to manager')
            # TODO: handle failed copy operations
            time.sleep(5)
            put(agents_key_path, userhome_on_management + '/.ssh')

        def _get_private_key_path_from_keypair_config(keypair_config):
            path = keypair_config['provided']['private_key_filepath'] if \
                'provided' in keypair_config else \
                keypair_config['auto_generated']['private_key_target_path']
            return expanduser(path)

        compute_config = config['compute']
        mgmt_server_config = compute_config['management_server']

        with settings(host_string=mgmt_ip):
            _copy(
                mgmt_server_config['userhome_on_management'],
                _get_private_key_path_from_keypair_config(
                    compute_config['agent_servers']['agents_keypair']))

    def provision(self):
        """
        provisions resources for the management server

        :rtype: 'tuple' with the machine's public and private ip's,
        the ssh key and user configured in the config yaml and
        the prorivder's context (a dict containing the privisioned
        resources to be used during teardown)
        """
        lgr.info('bootstrapping to Cloudstack provider.')

        lgr.debug('reading configuration file')
        # provider_config = _read_config(None)
        zone_type = self.provider_config['cloudstack']['zone_type']

        #init keypair and security-group resource creators.
        cloud_driver = CloudstackConnector(self.provider_config).create()
        keypair_creator = CloudstackKeypairCreator(
            cloud_driver, self.provider_config)

        if zone_type == 'basic':

            security_group_creator = CloudstackSecurityGroupCreator(
                    cloud_driver, self.provider_config)

            #create required node topology
            lgr.debug('creating the required resources for management vm')
            security_group_creator.create_security_groups()
            keypair_creator.create_key_pairs()

            keypair_name = keypair_creator.get_management_keypair_name()
            sg_name = security_group_creator.get_mgmt_security_group_name()

            lgr.debug('reading server configuration.')
            mgmt_server_config = self.provider_config.get('compute', {}) \
            .get('management_server', {})

            # init compute node creator
            compute_creator = CloudstackSecurityGroupComputeCreator(
                                                    cloud_driver,
                                                     self.provider_config,
                                                     keypair_name,
                                                     sg_name)

            #spinning-up a new instance using the above topology.
            #Cloudstack provider supports only public ip allocation.
            #see cloudstack 'basic zone'

            public_ip = compute_creator.create_node()

        if zone_type == 'advanced':

            lgr.debug('Using the advanced zone path')

            network_creator = CloudstackNetworkCreator(
                cloud_driver, self.provider_config)

            #create required node topology
            lgr.debug('creating the required resources for management vm')

            network_creator.create_networks()
            keypair_creator.create_key_pairs()

            keypair_name = keypair_creator.get_management_keypair_name()
            netw_name = network_creator.get_mgmt_network_name()
            lgr.debug(' network name {0}'.format(netw_name))
            netw = network_creator.get_network(netw_name)
            lgr.debug(' network id {0}'.format(netw[0].id))

            #agent_netw_name = network_creator.get_agent_network_name()
            #lgr.debug(' agent network name {0}'.format(agent_netw_name))
            #agent_netw = network_creator.get_network(agent_netw_name)
            #lgr.debug(' agent network id {0}'.format(agent_netw))

            lgr.debug('reading server configuration.')
            mgmt_server_config = self.provider_config.get('compute', {}) \
            .get('management_server', {})

            nets = netw

            # init compute node creator
            compute_creator = CloudstackNetworkComputeCreator(cloud_driver,
                                                     self.provider_config,
                                                     keypair_name,
                                                     nets)

            node = compute_creator.create_node()

            # Getting network config for portmaps, in advanced zones portmaps
            # are mapped to a node so we need to create portmaps
            # after node creation
            lgr.debug('reading management network configuration.')
            management_network_config = self.provider_config['networking'][
                'management_network']
            #management_network_name = management_network_config['name']

            # If we need to use an existing network we do not config portfwd
            if not management_network_config['use_existing'] == True:

                mgmt_ports = management_network_config['ports']
                public_ip = network_creator.get_mgmt_pub_ip()

                #for each port, add forward rule
                for port in mgmt_ports:
                        #cidr = management_sg_config.get('cidr', None)
                        protocol = management_network_config.get('protocol',
                                                                None)
                        network_creator.add_port_fwd_rule(public_ip,
                                                          port,
                                                          port,
                                                          protocol,
                                                          node)
            # Set Management IP to either private or Public
            if mgmt_server_config['use_private_ip'] == True:
                public_ip = node
                mgmt_ip = node.private_ips[0]
            else:
                public_ip = network_creator.get_mgmt_pub_ip()
                mgmt_ip = public_ip.address

        else:
            lgr.debug(
            'cloudstack -> zone_type must be either basic or advanced')

        provider_context = {"ip": str(mgmt_ip)}
        provider_context['mgmt_node_id'] = str(node.id)

        print('management ip: ' + mgmt_ip + ' key name: ' + self.
              _get_private_key_path_from_keypair_config(
            mgmt_server_config['management_keypair']) + 'user name: ' +
              mgmt_server_config.get('user_on_management'))

        self.copy_files_to_manager(
            mgmt_ip,
            self.provider_config,
            self._get_private_key_path_from_keypair_config(
                mgmt_server_config['management_keypair']),
            mgmt_server_config.get('user_on_management'))

        return mgmt_ip, \
               mgmt_ip, \
               self._get_private_key_path_from_keypair_config(
                   mgmt_server_config['management_keypair']), \
               mgmt_server_config.get('user_on_management'), \
                   provider_context

    def validate(self, validation_errors={}):
        """
        validations to be performed before provisioning and bootstrapping
        the management server.

        :param dict schema: a schema dict to validate the provider config
        against
        :rtype: 'dict' representing validation_errors. provisioning will
        continue only if the dict is empty.
        """
        return validation_errors

    def teardown(self, provider_context, ignore_validation=False):
        """
        tears down the management server and its accompanied provisioned
        resources

        :param dict provider_context: context information with the previously
        provisioned resources
        :param bool ignore_validation: should the teardown process ignore
        conflicts during teardown
        :rtype: 'None'
        """
        management_id = provider_context['mgmt_node_id']
        lgr.info('tearing-down management vm {0}.'.format(management_id))

        # lgr.debug('reading configuration file {0}'.format(config_path))
        # provider_config = _read_config(config_path)

        zone_type = self.provider_config['cloudstack']['zone_type']
        zone_type = zone_type.lower()

        if zone_type == 'basic':

            #init keypair and security-group resource creators.
            cloud_driver = CloudstackConnector(self.provider_config).create()
            keypair_creator = CloudstackKeypairCreator(
                cloud_driver, self.provider_config)
            security_group_creator = CloudstackSecurityGroupCreator(
                cloud_driver, self.provider_config)
            # init compute node creator
            compute_creator = CloudstackSecurityGroupComputeCreator(
                                                     cloud_driver,
                                                     self.provider_config,
                                                     keypair_name=None,
                                                     security_group_name=None,
                                                     node_name=None)

            resource_terminator = CloudstackSecurityGroupResourceTerminator(
                                                        security_group_creator,
                                                        keypair_creator,
                                                        compute_creator,
                                                        management_id)

            lgr.debug('terminating management vm and all of its resources.')
            resource_terminator.terminate_resources()

        if zone_type == 'advanced':

            #init keypair and security-group resource creators.
            cloud_driver = CloudstackConnector(self.provider_config).create()
            keypair_creator = CloudstackKeypairCreator(
                cloud_driver, self.provider_config)
            network_creator = CloudstackNetworkCreator(
                cloud_driver, self.provider_config)
            # init compute node creator
            compute_creator = CloudstackNetworkComputeCreator(cloud_driver,
                                                     self.provider_config,
                                                     keypair_name=None,
                                                     network_name=None,
                                                     node_name=None)

            resource_terminator = CloudstackNetworkResourceTerminator(
                                                             network_creator,
                                                             keypair_creator,
                                                             compute_creator,
                                                             management_id)

            lgr.debug('terminating management vm and all of its resources.')
            resource_terminator.terminate_resources()


# Create the provider folder in script location.
def init(target_directory, reset_config, is_verbose_output=False):
    if not reset_config and os.path.exists(
            os.path.join(target_directory, CONFIG_FILE_NAME)):
        lgr.debug('config file path {0} already exists. '
                  'either set a different config target directory '
                  'or enable reset_config property'.format(target_directory))
        return False

    provider_dir = os.path.dirname(os.path.realpath(__file__))
    files_path = os.path.join(provider_dir, CONFIG_FILE_NAME)

    lgr.debug('Copying provider files from {0} to {1}'
        .format(files_path, target_directory))
    shutil.copy(files_path, target_directory)
    return True


def _deep_merge_dictionaries(overriding_dict, overridden_dict):
    merged_dict = deepcopy(overridden_dict)
    for k, v in overriding_dict.iteritems():
        if k in merged_dict and isinstance(v, dict):
            if isinstance(merged_dict[k], dict):
                merged_dict[k] = _deep_merge_dictionaries(v, merged_dict[k])
            else:
                raise RuntimeError('type conflict at key {0}'.format(k))
        else:
            merged_dict[k] = deepcopy(v)
    return merged_dict


def _read_config(config_file_path):
    if not config_file_path:
        config_file_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            CONFIG_FILE_NAME)
    defaults_config_file_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        DEFAULTS_CONFIG_FILE_NAME)

    if not os.path.exists(config_file_path) or not os.path.exists(
            defaults_config_file_path):
        if not os.path.exists(defaults_config_file_path):
            raise ValueError('Missing the defaults configuration file; '
                             'expected to find it at {0}'
                .format(defaults_config_file_path))
        raise ValueError('Missing the configuration file; expected to find '
                         'it at {0}'.format(config_file_path))

    lgr.debug('reading provider config files')
    with open(config_file_path, 'r') as config_file, open(
            defaults_config_file_path, 'r') as defaults_config_file:

        lgr.debug('safe loading user config')
        user_config = yaml.safe_load(config_file.read())

        lgr.debug('safe loading default config')
        defaults_config = yaml.safe_load(defaults_config_file.read())

    lgr.debug('merging configurations')
    merged_config = _deep_merge_dictionaries(user_config, defaults_config) \
        if user_config else defaults_config
    return merged_config


# def bootstrap(config_path=None, is_verbose_output=False,
#               bootstrap_using_script=True, keep_up=False,
#               dev_mode=False):
#     lgr.info('bootstrapping to Cloudstack provider.')
#     _set_global_verbosity_level(is_verbose_output)
#
#     lgr.debug('reading configuration file {0}'.format(config_path))
#     provider_config = _read_config(config_path)
#
#     #init keypair and security-group resource creators.
#     cloud_driver = CloudstackConnector(provider_config).create()
#     keypair_creator = CloudstackKeypairCreator(cloud_driver, provider_config)
#     security_group_creator = CloudstackSecurityGroupCreator(cloud_driver,
#                                                           provider_config)
#     #create required node topology
#     lgr.debug('creating the required resources for management vm')
#     security_group_creator.create_security_groups()
#     keypair_creator.create_key_pairs()
#
#     keypair_name = keypair_creator.get_management_keypair_name()
#     security_group_name = security_group_creator.
#                    get_mgmt_security_group_name()
#
#     # init compute node creator
#     compute_creator = CloudstackComputeCreator(cloud_driver,
#                                              provider_config,
#                                              keypair_name,
#                                              security_group_name)
#
#     #spinning-up a new instance using the above topology.
#     #Cloudstack provider supports only public ip allocation.
#     #see cloudstack 'basic zone'
#     public_ip = compute_creator.create_node()
#     cosmo_bootstrapper = CosmoOnCloudstackBootstrapper(provider_config,
#                                                      public_ip,
#                                                      public_ip,
#                                                      bootstrap_using_script,
#                                                      dev_mode)
#     #bootstrap to cloud.
#     cosmo_bootstrapper.do(keep_up)
#     return public_ip


#TODO: no config_path named property on openstack. why?
# def teardown(management_ip,
#              is_verbose_output=False,
#              config_path=None):
#     lgr.info('tearing-down management vm {0}.'.format(management_ip))
#
#     lgr.debug('reading configuration file {0}'.format(config_path))
#     provider_config = _read_config(config_path)
#
#     #init keypair and security-group resource creators.
#     cloud_driver = CloudstackConnector(provider_config).create()
#     keypair_creator = CloudstackKeypairCreator(cloud_driver, provider_config)
#     security_group_creator = CloudstackSecurityGroupCreator(cloud_driver,
#                                                           provider_config)
#     # init compute node creator
#     compute_creator = CloudstackComputeCreator(cloud_driver,
#                                              provider_config,
#                                              keypair_name=None,
#                                              security_group_name=None,
#                                              node_name=None)
#
#     resource_terminator = CloudstackResourceTerminator(
#                                            security_group_creator,
#                                                      keypair_creator,
#                                                      compute_creator,
#                                                      management_ip)
#
#     lgr.debug('terminating management vm and all of its resources.')
#     resource_terminator.terminate_resources()


class CloudstackSecurityGroupResourceTerminator(object):
    def __init__(self,
                 security_group_creator,
                 key_pair_creator,
                 compute_creator,
                 mgmt_ip):
        self.security_group_creator = security_group_creator
        self.key_pair_creator = key_pair_creator
        self.compute_creator = compute_creator
        self.mgmt_ip = mgmt_ip

    def terminate_resources(self):
        lgr.info('terminating management vm {0}'.format(self.mgmt_ip))
        self.compute_creator.delete_node(self.mgmt_ip)

        lgr.info('deleting agent and management keypairs')
        self.key_pair_creator.delete_keypairs()

        lgr.info('deleting agent and management security-groups')
        self.security_group_creator.delete_security_groups()


class CloudstackNetworkResourceTerminator(object):
    def __init__(self,
                 network_creator,
                 key_pair_creator,
                 compute_creator,
                 mgmt_id):
        self.network_creator = network_creator
        self.key_pair_creator = key_pair_creator
        self.compute_creator = compute_creator
        self.mgmt_id = mgmt_id

    def terminate_resources(self):
        lgr.info('terminating management vm {0}'.format(self.mgmt_id))
        self.compute_creator.delete_node(self.mgmt_id)

        lgr.info('deleting agent and management keypairs')
        self.key_pair_creator.delete_keypairs()

        lgr.info('deleting agent and management networks')
        self.network_creator.delete_networks()


class CloudstackLogicError(RuntimeError):
    pass


class CloudstackConnector(object):
    def __init__(self, provider_config):
        self.config = provider_config

    def create(self):
        lgr.debug('creating Cloudstack cloudstack connector')
        api_key = self.config['authentication']['api_key']
        api_secret_key = self.config['authentication']['api_secret_key']
        api_url = self.config['authentication']['api_url']
        cls = get_driver(Provider.CLOUDSTACK)
        return cls(key=api_key, secret=api_secret_key, url=api_url)


class CloudstackKeypairCreator(object):
    def __init__(self, cloud_driver, provider_config):
        self.cloud_driver = cloud_driver
        self.provider_config = provider_config

    def _get_keypair(self, keypair_name):
        keypairs = [kp for kp in self.cloud_driver.list_key_pairs()
                    if kp.name == keypair_name]
        if keypairs.__len__() == 0:
            return None
        return keypairs[0]

    def delete_keypairs(self):
        mgmt_keypair_name = self.get_management_keypair_name()
        mgmt_keypair = self._get_keypair(mgmt_keypair_name)

        if not mgmt_keypair == None:
            lgr.info('deleting management keypair {0}'
                     .format(mgmt_keypair_name))
            self.cloud_driver.delete_key_pair(mgmt_keypair)
        else:
            lgr.info('keypair {0} not found'.format(mgmt_keypair_name))

        agent_keypair_name = self._get_agents_keypair_name()
        agent_keypair = self._get_keypair(agent_keypair_name)

        if not agent_keypair == None:
            lgr.info('deleting agents keypair {0}'.format(agent_keypair_name))
            self.cloud_driver.delete_key_pair(agent_keypair)
        else:
            lgr.info('keypair {0} not found'.format(agent_keypair_name))

    def get_management_keypair_name(self):
        keypair_config = self.provider_config['compute']['management_server'][
            'management_keypair']
        return keypair_config['name']

    def _get_agents_keypair_name(self):
        keypair_config = self.provider_config['compute']['agent_servers'][
            'agents_keypair']
        return keypair_config['name']

    def create_key_pairs(self,
                         mgmt_private_key_target_path=None,
                         mgmt_public_key_filepath=None,
                         mgmt_keypair_name=None,
                         agent_private_key_target_path=None,
                         agent_public_key_filepath=None,
                         agent_keypair_name=None):

        lgr.debug('reading management keypair configuration')
        mgmt_kp_config = self.provider_config['compute']['management_server'][
            'management_keypair']
        self._create_keypair(mgmt_kp_config,
                             mgmt_private_key_target_path,
                             mgmt_public_key_filepath,
                             mgmt_keypair_name)

        lgr.debug('reading agent keypair configuration')
        agent_kp_config = self.provider_config['compute']['agent_servers'][
            'agents_keypair']
        self._create_keypair(agent_kp_config,
                             agent_private_key_target_path,
                             agent_public_key_filepath,
                             agent_keypair_name)

    def _create_keypair(self, keypair_config,
                        private_key_target_path=None,
                        public_key_filepath=None,
                        keypair_name=None):

        if not keypair_name:
            keypair_name = keypair_config['name']
        if not private_key_target_path:
            private_key_target_path = keypair_config.get('auto_generated',
                {}).get('private_key_target_path', None)
        if not public_key_filepath:
            public_key_filepath = keypair_config.get('provided', {}).get(
                'public_key_filepath', None)

        if self._get_keypair(keypair_name):
            lgr.info('using existing keypair {0}'.format(keypair_name))
            return
        else:
            if not private_key_target_path and not public_key_filepath:
                raise RuntimeError(
                    '{0} keypair not found. '
                    'you must provide either a private key target path, '
                    'public key file-path or an existing keypair name '
                    'in configuration file')

        if public_key_filepath:
            if not os.path.exists(public_key_filepath):
                raise RuntimeError('public key {0} was not found on your local'
                                   'file system.'.format(public_key_filepath))

            lgr.debug('importing public key with name {0} from {1}'.format(
                keypair_name, public_key_filepath))
            self.cloud_driver.import_key_pair_from_file(keypair_name,
                                                        public_key_filepath)
        else:
            lgr.info('creating a keypair named {0}'.format(keypair_name))
            result = self.cloud_driver.create_key_pair(keypair_name)

            pk_target_path = os.path.expanduser(private_key_target_path)

            try:
                lgr.debug('creating dir {0}'.format(pk_target_path))
                os.makedirs(os.path.dirname(private_key_target_path))
            except OSError, exc:
                if not exc.errno == errno.EEXIST or not \
                    os.path.isdir(os.path.dirname(private_key_target_path)):
                    raise

            lgr.debug('writing private key to file {0}'.format(pk_target_path))
            with open(pk_target_path, 'w') as f:
                f.write(result.private_key)
                os.system('chmod 600 {0}'.format(pk_target_path))


class CloudstackSecurityGroupCreator(object):
    def __init__(self, cloud_driver, provider_config):
        self.cloud_driver = cloud_driver
        self.provider_config = provider_config

    def _add_rule(self, security_group_name,
                  protocol, cidr_list, start_port,
                  end_port=None):

        lgr.debug('creating security-group rule for {0} with details {1}'
            .format(security_group_name, locals().values()))
        self.cloud_driver.ex_authorize_security_group_ingress(
            securitygroupname=security_group_name,
            startport=start_port,
            endport=end_port,
            cidrlist=cidr_list,
            protocol=protocol)

    def get_security_group(self, security_group_name):
        security_groups = [sg for sg in self.cloud_driver
            .ex_list_security_groups() if sg['name'] == security_group_name]
        if security_groups.__len__() == 0:
            return None
        return security_groups[0]

    def delete_security_groups(self):

        mgmt_security_group_name = self.get_mgmt_security_group_name()
        lgr.debug('deleting management security-group {0}'.format(
            mgmt_security_group_name))
        try:
            self.cloud_driver.ex_delete_security_group(
                                mgmt_security_group_name)
        except:
            lgr.warn(
                'management security-group {0} may not have been deleted'
                    .format(mgmt_security_group_name))
            pass

        # agents_security_group_name = self._get_agent_security_group_name()
        # lgr.debug('deleting agents security-group {0}'.format(
        #     agents_security_group_name))
        # try:
        #     self.cloud_driver.ex_delete_security_group(
        #         agents_security_group_name)
        # except:
        #     lgr.warn(
        #         'agent security-group {0} may not have been deleted'.format(
        #             agents_security_group_name))
        #     pass

    def get_mgmt_security_group_name(self):
        mgmt_sg_conf = self.provider_config['networking'][
            'management_security_group']
        return mgmt_sg_conf['name']

    # def _get_agent_security_group_name(self):
    #    agent_sg_conf = self.provider_config['networking'][
    #        'agents_security_group']
    #    return agent_sg_conf['name']

    def _is_sg_exists(self, security_group_name):
        exists = self.get_security_group(security_group_name)
        if not exists:
            return False
        return True

    def create_security_groups(self):

        # Security group for Cosmo created instances
        # Security group for Cosmo manager, allows created
        # instances -> manager communication
        lgr.debug('reading management security-group configuration.')
        management_sg_config = self.provider_config['networking'][
            'management_security_group']
        management_sg_name = management_sg_config['name']

        if not self._is_sg_exists(management_sg_name):
            lgr.info('creating management security group: {0}'
                .format(management_sg_name))
            self.cloud_driver.ex_create_security_group(management_sg_name)

            mgmt_ports = management_sg_config['ports']
            #for each port, add rule
            for port in mgmt_ports:
                cidr = management_sg_config.get('cidr', None)
                protocol = management_sg_config.get('protocol', None)
                self._add_rule(security_group_name=management_sg_name,
                               start_port=port,
                               end_port=None,
                               cidr_list=cidr,
                               protocol=protocol)
        else:
            lgr.info('using existing management security group {0}'.format(
                management_sg_name))

        """
        lgr.debug('reading agent security-group configuration.')
        agent_sg_config = self.provider_config['networking'][
            'agents_security_group']
        agent_sg_name = agent_sg_config['name']

        if not self._is_sg_exists(agent_sg_name):
            lgr.info('creating agent security group {0}'.format(agent_sg_name))
            self.cloud_driver.ex_create_security_group(agent_sg_name)

            agent_ports = agent_sg_config['ports']
            #for each port, add rule
            for port in agent_ports:
                cidr = agent_sg_config['cidr']
                protocol = agent_sg_config['protocol']
                self._add_rule(security_group_name=agent_sg_name,
                               start_port=port,
                               end_port=None,
                               cidr_list=cidr,
                               protocol=protocol)
        else:
            lgr.info(
                'using existing agent security group {0}'.
                format(agent_sg_name))
        """


class CloudstackNetworkCreator(object):
    def __init__(self, cloud_driver, provider_config):
        self.cloud_driver = cloud_driver
        self.provider_config = provider_config

    def add_port_fwd_rule(self, ip_address, privateport,
                  publicport, protocol, node=None):

        lgr.debug('creating network rule for {0} with details {1}'
                           .format(ip_address, locals().values()))
        self.cloud_driver.ex_create_port_forwarding_rule(
                                            address=ip_address,
                                            private_port=privateport,
                                            public_port=publicport,
                                            node=node,
                                            protocol=protocol,
                                            openfirewall=False)

    def get_network(self, network_name):
        networks = [netw for netw in self.cloud_driver
            .ex_list_networks() if netw.name == network_name]

        if networks.__len__() == 0:
            return None
        #TODO: refactor - needs to return network[0] first item
        return networks

    def get_networks(self):
        networks = self.cloud_driver.ex_list_networks()
        return networks

    def delete_networks(self):

        mgmt_network_name = self.get_mgmt_network_name()
        #agent_network_name = self.get_agent_network_name()

        if not self.provider_config['networking'][
            'management_network']['use_existing'] == True:

            mgmt_network = self.get_network(mgmt_network_name)

            lgr.info('Deleting Management Network {0}'
                     .format(mgmt_network_name))
            self.cloud_driver.ex_delete_network(mgmt_network[0])
        else:
            lgr.debug('Using existing networks so no need to delete {0}'
                     .format(mgmt_network_name))

        """
        if not self.provider_config['networking'][
            'agent_network']['use_existing'] == True:

            agent_network = self.get_network(mgmt_network_name)
        else:
            lgr.debug('Using existing networks so no need to delete {0}'
                     .format(agent_network_name))

        lgr.info('Deleting Agent Network {0}'.format(agent_network_name))
        self.cloud_driver.ex_delete_network(agent_network[0])
        """

    def get_mgmt_network_name(self):
        mgmt_netw_conf = self.provider_config['networking'][
            'management_network']
        return mgmt_netw_conf['name']

    def get_mgmt_pub_ip(self):
        mgmt_net = self.provider_config['networking'][
            'management_network']['name']

        nets = self.get_networks()

        for net in nets:

            if net.name == mgmt_net:
                lgr.debug('Management Network {0} found!'.format(net.name))
                break
        else:
            raise RuntimeError('Management network {0} not found'.
                                   format(mgmt_net))

        publicips = self.cloud_driver.ex_list_public_ips()

        for public_ip in publicips:

            if public_ip.associated_network_id == net.id:
                lgr.debug('Found acquired Public IP: {0} with ID {1} '
                          'Associated with network id {2}'.
                          format(public_ip.address, public_ip.id, net.id))
                return public_ip
        else:
            raise RuntimeError('No matching mgmt public ip found')

    def get_agent_pub_ip(self):
        agent_pub_ip = self.provider_config['networking'][
            'agent_network']
        return agent_pub_ip['public_ip']

    def get_agent_network_name(self):
        agent_netw_conf = self.provider_config['networking'][
            'agents_network']
        return agent_netw_conf['name']

    def _is_netw_exists(self, network_name):
        exists = self.get_network(network_name)
        if not exists:
            return False
        return True

    def create_networks(self):

        lgr.debug('reading management network configuration.')
        management_netw_config = self.provider_config['networking'][
            'management_network']
        # agent_netw_config = self.provider_config['networking'][
        #     'agents_network']
        management_netw_name = management_netw_config['name']
        use_existing = management_netw_config['use_existing']

        # agent_netw_name = agent_netw_config['name']
        # agent_use_existing = agent_netw_config['use_existing']

        if not self._is_netw_exists(management_netw_name):
            if not use_existing == False:
                raise RuntimeError('No existing network and use_existing '
                                   'set to true')

            if not use_existing == True:
                lgr.info('Creating network {0} since use_existing is false '
                         'and network does not exist'
                         .format(management_netw_name))

                netmask = management_netw_config['network_mask']
                gateway = management_netw_config['network_gateway']
                net_offering = management_netw_config['network_offering']
                domain = management_netw_config['network_domain']
                zone = management_netw_config['network_zone']
                locations = self.cloud_driver.list_locations()
                offerings = self.cloud_driver.ex_list_network_offerings()

                for location in locations:
                    if zone == location.name:
                        break
                    else:
                        raise RuntimeError('Specified location cannot be '
                                           'found!')

                for offering in offerings:
                    if net_offering == offering.name:
                        break
                    else:
                        raise RuntimeError('Specified network offering '
                                           'cannot be found!')

                self.cloud_driver.ex_create_network(management_netw_name,
                                                    management_netw_name,
                                                    offering,
                                                    location,
                                                    gateway,
                                                    netmask,
                                                    domain)
        else:
            lgr.info('using existing management network {0}'.format(
                management_netw_name))
"""
        lgr.debug('reading agent network configuration.')
        agent_netw_config = self.provider_config['networking'][
            'agents_network']
        agent_netw_name = agent_netw_config['name']

        if not self._is_netw_exists(agent_netw_name):
            if not agent_use_existing == False:
                raise RuntimeError('No existing agent network and'
                                   'use_existing set to true')

            if not agent_use_existing == True:
                lgr.info('Creating agent network {0} since use_existing'
                         'is false and network does not exist'
                         .format(agent_netw_name))

                netmask = agent_netw_config['network_mask']
                gateway = agent_netw_config['network_gateway']
                net_offering = agent_netw_config['network_offering']
                domain = agent_netw_config['network_domain']
                zone = agent_netw_config['network_zone']
                locations = self.cloud_driver.list_locations()
                offerings = self.cloud_driver.ex_list_network_offerings()

                for location in locations:
                    if zone == location.name:
                        break
                    else:
                        raise RuntimeError('Specified location cannot be '
                                           'found!')

                for offering in offerings:
                    if net_offering == offering.name:
                        break
                    else:
                        raise RuntimeError('Specified network offering '
                                           'cannot be found!')

                self.cloud_driver.ex_create_network(agent_netw_name,
                                                    agent_netw_name,
                                                    offering,
                                                    location,
                                                    gateway,
                                                    netmask,
                                                    domain)

        else:
            lgr.info(
                'using existing agent network {0}'.format(agent_netw_name))
"""


class CloudstackSecurityGroupComputeCreator(object):
    def __init__(self, cloud_driver,
                 provider_config,
                 keypair_name=None,
                 security_group_name=None,
                 node_name=None):
        self.cloud_driver = cloud_driver
        self.provider_config = provider_config
        self.keypair_name = keypair_name
        self.security_group_names = [security_group_name, ]
        self.node_name = node_name

    def delete_node(self, node_ip):
        lgr.debug('getting node for id {0}'.format(node_ip))
        node = [node for node in self.cloud_driver.list_nodes() if
                node_ip in node.public_ips][0]

        lgr.debug('destroying node {0}'.format(node))
        self.cloud_driver.destroy_node(node)

    def create_node(self):

        lgr.debug('reading server configuration.')
        server_config = self.provider_config.get('compute', {}) \
            .get('management_server', {}).get('instance', None)

        lgr.debug('reading management vm image and size IDs from config')
        image_id = server_config.get('image')
        size_id = server_config.get('size')

        lgr.debug('getting node image for ID {0}'.format(image_id))

        image = [image for image in self.cloud_driver.list_images() if
                 image_id == image.id][0]
        lgr.debug('getting node size for ID {0}'.format(size_id))
        size = [size for size in self.cloud_driver.list_sizes() if
                size.name == size_id][0]

        if self.node_name is None:
            self.node_name = server_config.get('name', None)
        if self.keypair_name is None:
            self.keypair_name = server_config['management_keypair']['name']
        if self.security_group_names is None:
            network_config = self.provider_config.get('networking', {}) \
                .get('management_security_group', {})
            self.security_group_names = [network_config['name'], ]

        lgr.info(
            'starting a new virtual instance named {0}'.format(self.node_name))
        result = self.cloud_driver.create_node(
            name=self.node_name,
            ex_keyname=self.keypair_name,
            ex_security_groups=self.security_group_names,
            image=image,
            size=size)

        return result.public_ips[0]


class CloudstackNetworkComputeCreator(object):
    def __init__(self, cloud_driver,
                 provider_config,
                 keypair_name=None,
                 network_name=None,
                 node_name=None,
                 zone=None,
                 ip_address=None):
        self.cloud_driver = cloud_driver
        self.provider_config = provider_config
        self.keypair_name = keypair_name
        self.network_names = network_name
        self.node_name = node_name
        self.zone = zone
        self.ip_address = ip_address

    def get_zone_from_network(self, network_name):
        lgr.debug('getting zone info of network: {0}'.format(network_name))

        network_creator = CloudstackNetworkCreator(self.cloud_driver,
                                                   self.provider_config)
        network = network_creator.get_network(network_name)[0]
        lgr.debug('We found network: {0}'.format(network))
        zone_id = network.zoneid

        zone = [zone for zone in self.cloud_driver.list_locations() if
                zone_id == zone.id][0]

        lgr.debug('Found zone {0}'.format(zone))

        return zone

    def delete_node(self, node_id):
        lgr.debug('getting node for ID {0}'.format(node_id))

        node = [node for node in self.cloud_driver.list_nodes() if
                node_id == node.id][0]

        lgr.debug('destroying node {0}'.format(node))
        self.cloud_driver.destroy_node(node)

    def create_node(self):

        lgr.debug('reading server configuration.')
        server_config = self.provider_config.get('compute', {}) \
            .get('management_server', {}).get('instance', None)

        lgr.debug('reading management vm image and size IDs from config')
        image_id = server_config.get('image')
        size_id = server_config.get('size')

        lgr.debug('getting node image for ID {0}'.format(image_id))
        image = [image for image in self.cloud_driver.list_images() if
                 image_id == image.id][0]
        lgr.debug('getting node size for ID {0}'.format(size_id))
        size = [size for size in self.cloud_driver.list_sizes() if
                size.name == size_id][0]

        if self.node_name is None:
            self.node_name = server_config.get('name', None)
        if self.keypair_name is None:
            self.keypair_name = server_config['management_keypair']['name']
        if self.network_names is None:
            network_config = self.provider_config.get('networking', {}) \
                .get('management_network', {})
            self.network_names = [network_config['name'], ]
        if self.zone is None:
            mgmt_network_name = \
            self.provider_config.get('networking', {}) \
                                     .get('management_network', {}) \
                                     .get('name', None)
            self.zone = self.get_zone_from_network(mgmt_network_name)
        if self.ip_address is None:
            self.ip_address = server_config['private_ip']

        lgr.info(
            'starting a new virtual instance named {0} on network {1}'
            ' in zone {2}'
            .format(self.node_name, self.network_names[0].name, self.zone))
        node = self.cloud_driver.create_node(
            name=self.node_name,
            ex_keyname=self.keypair_name,
            networks=self.network_names,
            image=image,
            size=size,
            location=self.zone,
            ex_ip_address=self.ip_address)

        return node

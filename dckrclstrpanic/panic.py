#! /usr/bin/env python

from __future__ import print_function
import sh
from io import StringIO
import sys
import boto3
import os
import requests
import time
import sh
import uuid
import logging
import datetime
from dateutil.tz import tzutc
import json
from sh import docker_machine
import pprint
import sh
import sys
from threading import Semaphore
from botocore.exceptions import ClientError

#----------------------------------------------------------------------------#
#--- SUBPROCESS w/ ASYNC READ -----------------------------------------------#
#----------------------------------------------------------------------------#

from zope.component import getGlobalSiteManager, getUtility
from zope.interface import implements, Interface
import threading
from threading import Thread
import subprocess
from subprocess import Popen, PIPE

gsm = getGlobalSiteManager()

def dbgprnt(msg):
    print('/////// msg ///////')
    print(msg)
    print('///////////////////')

class IFWUtils(Interface):
    pass

class HoverException(Exception):
    pass

class HoverAPI(object):
    def __init__(self):
        username = os.environ.get('hover_username')
        password = os.environ.get('hover_password')
        params = {"username": username, "password": password}
        r = requests.post("https://www.hover.com/api/login", json=params)
        if not r.ok or "hoverauth" not in r.cookies:
            raise HoverException(r)
        self.cookies = {"hoverauth": r.cookies["hoverauth"]}
        res = self.call("get", "dns")
        self.entries_by_domain = {}
        self.ids_by_domain = {}
        if res.get('succeeded'):
            for item in res.get('domains'):
                domain = item.get('domain_name')
                domain_id = item.get('id')
                self.entries_by_domain[domain] = item
                self.ids_by_domain[domain] = domain_id

    def call(self, method, resource, data=None):
        url = "https://www.hover.com/api/{0}".format(resource)
        r = requests.request(method, url, data=data, cookies=self.cookies)
        if not r.ok:
            raise HoverException(r)
        if r.content:
            body = r.json()
            if "succeeded" not in body or body["succeeded"] is not True:
                raise HoverException(body)
            return body

    def getEntryById(self, domain_id):
        return self.call("get", "domains/{}".format(domain_id))

    def getDnsById(self, domain_id):
        return self.call("get", "domains/{}/dns".format(domain_id))

    def getDnsByDomain(self, domain):
        #print(self.ids_by_domain.keys())
        domain_id = self.ids_by_domain.get(domain)
        return self.getDnsById(domain_id)

    def createDnsARecord(self):
        record = {"name": "mysubdomain", "type": "A", "content": "127.0.0.1"}
        self.call("post", "domains/dom123456/dns", record)

    def setNameservers(self, nameservers=[]):
        json.dumps({"field":"nameservers","value":nameservers})
        r = requests.put(
            "https://www.hover.com/control_panel/domain/entomoph.me",
            cookies=self.cookies,
            json=params
        )

class Route53API(object):
    def __init__(self):
        self.conn = boto3.client('route53')

    def listAllZones(self):
        return self.conn.list_hosted_zones().get('HostedZones')

    def createZone(self, zone_name, caller_ref):
        return self.conn.create_hosted_zone(
            Name=zone_name,
            CallerReference=caller_ref
        )

    def changeRecordSets(zone_id, change_list):
        self.conn.change_resource_record_sets(
            HostedZoneId = zone_id,
            ChangeBatch = {'Changes': change_list}
        )

    def deleteZoneById(self, zone_id):
        for zone in self.listAllZones():
            if zone.get('Id') == zone_id:
                self.conn.delete_hosted_zone(Id=zone_id)

    def deleteAllZones(self):
        for zone in self.listAllZones():
            zone_id = zone.get('Id')
            self.conn.delete_hosted_zone(Id=zone_id)
        return json.dumps({"succeeded":True})


class HoverAWS(object):
    def __init__(self):
        self.r53 = Route53API()
        self.hov = HoverAPI()

    def __call__(self):
        print(r53.listAllZones())
        print(hov.entries_by_domain)


class EC2(object):
    def __init__(self):
        #boto3.set_stream_logger(name='botocore')
        self.conn = boto3.client('ec2')
        self.rsrc = boto3.resource('ec2')
        #self.conn = boto3.resource('ec2')

    def getInstances(self):
        # running instance --> Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        return list(self.conn.instances.filter(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]
        ))

    def listSecurityGroups(self):
        return self.conn.describe_security_groups().get('SecurityGroups')

    def getSecurityGroupByName(self, name):
        for group in self.listSecurityGroups():
            group_name = group.get('GroupName')
            if group_name == name:
                return group
        return None

    def authorizeSwarmIngress(self, group_id):
        self.conn.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 2377,
                    'ToPort': 2377,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
        ])

    def getInstancesWithTag(self, tag_name, tag_value):
        filters = [{'Name': 'tag:{}'.format(tag_name), 'Values': [tag_value]}]
        return self.conn.describe_instances(Filters=filters)

    def getInstancesWithTagKey(self, tag_name):
        "returns ec2.instancesCollection"
        filters = [{'Name':'tag-key', 'Values':["{}".format(tag_name)]}]
        return self.rsrc.instances.filter(Filters=filters)

    def getInstancesWithTagValue(self, tag_value):
        "returns ec2.instancesCollection"
        filters = [{'Name':'tag-value', 'Values':["{}".format(tag_value)]}]
        return self.rsrc.instances.filter(Filters=filters)

    def getInstanceTags(self, instance_id):
        instance = self.getInstanceById(instance_id)
        tags = {}
        if instance.tags is None:
            return []
        for tag in instance.tags:
            key = tag['Key']
            tags[key] = tag['Value']
        return tags

    def applyTagToInstance(self, instance_id, tags):
        #tags is in this format --> [{'Key':'foo', 'Value':'bar'}]
        self.conn.create_tags(Resources=[instance_id], Tags=tags)

    def getInstanceById(self, instance_id):
        return self.rsrc.Instance(instance_id)

    def getVolumesByInstanceId(self, instance_id):
        return self.conn.describe_instance_attribute(
            InstanceId=instance_id,
            Attribute='blockDeviceMapping'
        )

    def rebootInstance(self, instance_id):
        instance = self.getInstanceById(instance_id)
        instance.reboot()
        instance.wait_until_running()
        return

    def getPrivateDns(self, instance_id):
        instance = self.getInstanceById(instance_id)
        return instance.private_dns_name

    def getPrivateIpAddress(self, instance_id):
        instance = self.getInstanceById(instance_id)
        return instance.private_ip_address.strip()

    def getPublicIpAddress(self, instance_id):
        instance = self.getInstanceById(instance_id)
        return instance.public_ip_address.strip()

    def listVPC(self):
        return list(self.conn.vpcs.all())
        #vpcs = list(self.conn.vpcs.filter(Filters=filters))
ec2 = EC2()
gsm.registerUtility(ec2, IFWUtils, 'ec2')

# //////////////////////////////////////////////////////////////////////////// #
# //////////////////////////////////////////////////////////////////////////// #
# //////////////////////////////////////////////////////////////////////////// #

class IPFSCluster(object):
    def __init__(self):
        pass

    def createClusterSecret(self):
        cmd = \
            "-vN 32 -An -tx1 /dev/urandom | tr -d".split()
        cmd.append(' \n')
        return sh.od(*cmd).strip().replace(' ', '').replace('\n', '')

    def initCluster(self, mchn_name, env={}):
        cmd = "ipfs-cluster-service init"
        self.runCmd(mchn_name, cmd.split(' '), env=env)

    def runClusterDaemon(self, mchn_name, env={}):
        cmd = "ipfs-cluster-service daemon"
        self.runCmd(mchn_name, cmd.split(' '), env=env)

    def setClusterMaster(self, mchn_name, env={}):
        if "CLUSTER_SECRET" in env.keys():
            self.initCluster(mchn_name, env=env)
            self.runClusterDaemon(mchn_name, env=env)
        else:
            print("/// NO CLUSTER SECRET EXISTS ///")
            sys.exit(0)

    def setClusterWorker(self, mchn_name, env={}):
        if "CLUSTER_SECRET" in env.keys():
            self.ipfs.runClusterDaemon(mchn_name, env=env)
        else:
            print("/// NO CLUSTER SECRET EXISTS ///")
            sys.exit(0)

_ipfs = IPFSCluster()
gsm.registerUtility(_ipfs, IFWUtils, '_ipfs')


class Swarm(object):
    def __init__(self):
        self.ec2 = getUtility(IFWUtils, 'ec2')
        self.ipfs = getUtility(IFWUtils, '_ipfs')
        #patches
        self.ipfs.runCmd = self.runCmd

    def getSwarmMasters(self, cluster_uid):
        cluster = self.getClusterInfo(cluster_uid)
        masters = []
        for mchn_name in cluster:
            entry = cluster[mchn_name]
            if 'swarm_master' in entry.keys():
                masters.append(mchn_name)
        return masters

    def checkService(self, srvc_name, cluster_uid):
        mchn_name = self.getSwarmMasters(cluster_uid)[0]
        cmd = \
            "sudo docker service ps {}".format(srvc_name)
        self.runCmd(mchn_name, cmd, quoted=False)

    def createRegistryService(self, cluster_uid):
        mchn_name = self.getSwarmMasters(cluster_uid)[0]
        cmd = \
            "docker service create --name registry --publish published=5000,target=5000 registry:2"
        self.runCmd(mchn_name, cmd, quoted=False)

    def getInstanceTagsDict(self, instance):
        tags_lst = [{x['Key']:x['Value']} for x in instance_tags]
        tags_dict = {}
        for item in tags_lst:
            key = item.keys()[0]
            val = item.get(key)
            tags_dict[key] = val

    def getClusters(self):
        clusters = {}
        for instance in swarm.ec2.getInstancesWithTagKey('cluster_uid').all():
            instance_tags = instance.tags
            instance_id = instance.id
            tags_lst = [{x['Key']:x['Value']} for x in instance_tags]
            tags_dict = {}
            for item in tags_lst:
                key = item.keys()[0]
                val = item.get(key)
                tags_dict[key] = val

            cluster_uid = tags_dict.pop('cluster_uid')
            mchn_name = tags_dict.pop('Name')
            if cluster_uid not in clusters.keys():
                clusters[cluster_uid] = {}
            clusters[cluster_uid][mchn_name] = {'instance_id':instance_id}
            if 'swarm_master' in tags_dict.keys():
                clusters[cluster_uid][mchn_name]['swarm_master'] = True
            clusters[cluster_uid][mchn_name]['volumes'] = \
                [x.id for x in instance.volumes.all()]
        print("/// CLUSTER INFO ///")
        print(clusters)
        return clusters

    def getClusterInfo(self, cluster_uid):
        return self.getClusters().get(cluster_uid)

    def getSwarmSecurityGroupId(self):
        return swarm.ec2.getSecurityGroupByName('docker-machine').get('GroupId')

    def listAllSwarms(self):
        for instance in self.ec2.getInstances():
            print(self.ec2.getInstanceTags(instance.id))

    def listAWSDockerMachines(self):
        #filter='state=Running',
        return sh.docker_machine.ls(
            filter='driver=amazonec2',
            format="{{.Name}}"
        ).strip().split('\n')

    def inspectDckrMchn(self, mchn_name):
        return json.loads(sh.docker_machine.inspect(mchn_name).strip())

    def getAwsInstanceId(self, mchn_name):
        return self.inspectDckrMchn(mchn_name).get('Driver').get('InstanceId')

    def rmDckrMchn(self, mchn_name):
        return sh.docker_machine.rm(mchn_name, force=True)

    def rmSwarn(self):
        for mchn_name in self.listAWSDockerMachines():
            if('dckrmchn') in mchn_name:
                swarm.rmDckrMchn(mchn_name)
                print(mchn_name)

    def printCmd(self, running_command):
        print("///////// runCmd /////////")
        print(' '.join(running_command.cmd).strip())
        print("///////// end res /////////")

    def runCmd(self, mchn_name, cmd, env={}, quoted=False):
        #hostname env VAR1=VALUE1 VAR2=VALUE thecommand the args
        #ssh username@machine VAR=value cmd cmdargs
        args = []
        if env:
            for kv in env.items():
                args.append("{}={}".format(kv[0], kv[1]))
        baked = sh.docker_machine.ssh.bake(mchn_name, *args)

        if quoted:
            res = baked(cmd)
            self.printCmd(res, cmd)
        else:
            res = baked(cmd)
            self.printCmd(res)
        return res

    def getJoinToken(self, mchn_name, role="worker"):
        cmd = 'docker swarm join-token --quiet {}'.format(role)
        return self.runCmd(mchn_name, cmd)

    def getMachinePublicIp(self, mchn_name):
        instance_id = self.getAwsInstanceId(mchn_name)
        return self.ec2.getPublicIpAddress(instance_id)

    def setSwarmWorker(self, mchn_name, join_token, mgr_ip):
        print(">>> setSwarmWorker <<<")
        advertised_addr = "{}:2377".format(mgr_ip)
        print(advertised_addr)
        cmd = \
        """
        docker swarm join --token {} {}
        """.format(join_token, advertised_addr)
        self.runCmd(mchn_name, cmd, quoted=True)

    def setSwarmMaster(self, mchn_name):
        mgr_ip = self.getMachinePublicIp(mchn_name)
        #advertised_addr = "tcp://{}:2377".format(mgr_ip)
        instance_id = self.getAwsInstanceId(mchn_name)
        advertised_addr = "{}:2377".format(mgr_ip)
        cmd = "docker swarm init --advertise-addr {}".format(mgr_ip)
        self.runCmd(mchn_name, cmd)
        master_tags = [
            {'Key':'swarm_master', 'Value':'true'}
        ]
        self.ec2.applyTagToInstance(instance_id, master_tags)
        worker_token = self.getJoinToken(mchn_name, role="worker")
        return (worker_token, mgr_ip)

    def getSwarmNodes(self, cluster_uid):
        return self.ec2.getInstancesWithTag('cluster_uid', cluster_uid)

    def getSwarmNodeInstances(self, cluster_uid):
        nodes = self.getSwarmNodes(cluster_uid).get('Reservations')
        res = []
        for entry in nodes:
            node = entry.get('Instances')[0]
            instance_id = node.get('InstanceId')
            res.append(self.ec2.rsrc.Instance(instance_id))
        return res

    def applySecurityGroupRules(self):
        #2377/tcp: Swarm mode api
        #7946/both: Overlay networking control
        #4789/udp: Overlay networking data
        #protocol 50 for ipsec (secure option) of overlay networking
        rules = [
            ("tcp",[2377]),
            ("tcp",[7946]),
            ("udp",[7946]),
            ("tcp",[4789]),
            ("udp",[4789]),
            ("tcp",[8080]),
            ("tcp",[80]),
            ("tcp",[4001,4002])
        ]
        sg_id = swarm.getSwarmSecurityGroupId()
        ip_permissions = []
        for rule in rules:
            if len(rule[1]) == 1:
                protocol, from_port, to_port = \
                    rule[0], rule[1][0], rule[1][0]
            else:
                protocol, from_port, to_port = \
                    rule[0], rule[1][0], rule[1][1]
            entry = {
                'IpProtocol':protocol,
                'FromPort':from_port,
                'ToPort':to_port,
                'IpRanges':[{'CidrIp': '0.0.0.0/0'}]
            }
            ip_permissions.append(entry)
        try:
            self.ec2.conn.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=ip_permissions
            )
        except ClientError:
            pass

    def createMachineName(self, uid=None):
        if not uid:
            uid = str(uuid.uuid4())
        return "dckrmchn-{}".format(uid)

    def addUserToDockerGroup(self, mchn_name):
        cmd = "sudo usermod -aG docker $USER"
        self.runCmd(mchn_name, cmd)

    def onSwarmNodeCreated(self, cluster_uid, proc, success, exit_code):
        """
        I run when aws instance creation has succeeded
        I am an asynchronous callback originated by sh.RunningCommand
        """
        mchn_name = proc.cmd[-1]
        tags = [
            {'Key':'cluster_uid', 'Value':cluster_uid}
        ]
        instance_id = self.getAwsInstanceId(mchn_name)
        self.ec2.applyTagToInstance(instance_id, tags)
        self.addUserToDockerGroup(mchn_name)

    def getMachineCommand(self, engine_env_args):
        return \
            sh.docker_machine.create.bake(
                driver="amazonec2",
                amazonec2_instance_type="t2.micro",
                *engine_env_args
            )

    def createSwarmNodes(self, n_workers, cluster_uid, env_args={}):
        """
        I asynchrounously create and tag all swarm instances on aws
        """
        pool = Semaphore(10)
        def done(proc, success, exit_code):
            if success:
                self.onSwarmNodeCreated(cluster_uid, proc, success, exit_code)
            pool.release()

        def launchNode(mchn_name):
            ### apply env arguments
            engine_env_args = []
            for entry in env_args.items():
                engine_env_args.append('--engine-env')
                engine_env_args.append('{}={}'.format(entry[0], entry[1]))
            dmc = self.getMachineCommand(engine_env_args)
            #### do the thing
            pool.acquire()
            running_cmd = dmc(mchn_name, _bg=True, _done=done)
            return running_cmd
        #set up the nodes
        cluster_mchn_names = []
        procs = []
        for x in range(0, n_workers):
            mchn_name = self.createMachineName()
            cluster_mchn_names.append(mchn_name)
            procs.append(launchNode(mchn_name))
        #wait for the nodes to launch
        [p.wait() for p in procs]
        print("FINALLY")
        return cluster_mchn_names

    def initSwarm(self, n_workers=3, env_args={}):
        "create a new swarm with n nodes"
        cluster_uid = str(uuid.uuid4())
        cluster_mchn_names = \
            self.createSwarmNodes(
                n_workers,
                cluster_uid,
                env_args=env_args
            )
        swarm.applySecurityGroupRules()
        mstr_mchn = cluster_mchn_names[0]
        # >>> up to this point all nodes are created equal <<<
        # set the swarm master
        join_token, mgr_ip = swarm.setSwarmMaster(mstr_mchn)
        # set the swarm workers
        for mchn_name in cluster_mchn_names:
            if mchn_name != mstr_mchn:
                swarm.setSwarmWorker(mchn_name, join_token, mgr_ip)
_swarm = Swarm()
gsm.registerUtility(_swarm, IFWUtils, '_swarm')


if __name__ == '__main__':
    pp = pprint.PrettyPrinter(indent=2)
    swarm = getUtility(IFWUtils, '_swarm')
    swarm.rmSwarn()
    #swarm.initSwarm(n_workers=3, env_args={"foo":"bar", "bin":"baz"})

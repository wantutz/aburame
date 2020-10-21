from pyVim.connect import SmartConnect
from pyVim.connect import Disconnect
from pyVmomi import vim
import ssl

class Infrastructure(object):
    def __init__(self):
        self.handle = None

    def connect(self, vcenter_ip=None, user=None, password=None):
        # Create unverified context
        # vCenter6.0   ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        # vCenter6.7   ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        #              ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context = ssl._create_unverified_context()

        # Smart Connect
        self.handle = SmartConnect(host=vcenter_ip, user=user, pwd=password, sslContext=ssl_context)

    def disconnect(self):
        # Disconnect
        Disconnect(self.handle)

    def get_system_info(self):
        system_info = {}

        system_info["name"] = self.handle.content.about.fullName
        system_info["version"] = self.handle.content.about.version

        return system_info

    def _get_all_objects(self, content, vim_type):
        objs = {}
        container = content.viewManager.CreateContainerView(content.rootFolder, vim_type, True)

        for managed_object_ref in container.view:
            objs.update({managed_object_ref: managed_object_ref.name})

        return objs

    def get_all_dc(self):
        content = self.handle.content
        vim_type = vim.Datacenter

        return self._get_all_objects(content, [vim_type])

    def get_all_ds(self):
        content = self.handle.content
        vim_type = vim.Datastore

        return self._get_all_objects(content, [vim_type])

    def get_all_hs(self):
        content = self.handle.content
        vim_type = vim.HostSystem

        return self._get_all_objects(content, [vim_type])

    def get_all_vm(self):
        content = self.handle.content
        vim_type = vim.VirtualMachine

        return self._get_all_objects(content, [vim_type])

    def get_all_clusters(self):
        content = self.handle.content
        vim_type = vim.ClusterComputeResource

        return self._get_all_objects(content, [vim_type])

    def get_all_networks(self):
        content = self.handle.content
        vim_type = vim.Network

        return self._get_all_objects(content, [vim_type])

    def add_vswitch_to_host(self, host, vswitch_config):
        vswitch_spec = vim.host.VirtualSwitch.Specification()
        vswitch_spec.numPorts = vswitch_config.get("num_ports", None)
        vswitch_spec.mtu = vswitch_config.get("mtu", None)

        vswitch_name = vswitch_config.get("name", None)

        host.configManager.networkSystem.AddVirtualSwitch(vswitch_name, vswitch_spec)

if __name__ == "__main__":
    infra_client = Infrastructure()

    vcenter_ip = "<vcenter ip>"
    username = "<username>"
    password = "<passwd>"

    # Infra client
    infra_client.connect(vcenter_ip, username, password)

    # All Virtual Machines
    all_vms = infra_client.get_all_vm()
    for vm in all_vms:
       print("Vitual machine: {}".format(vm.name))

    # All Datacenters
    all_dcs = infra_client.get_all_dc()
    for dc in all_dcs:
        print("Datacenter: {}".format(dc.name))

    # All Datastores
    all_dss = infra_client.get_all_ds()
    for ds in all_dss:
        print("Datastore: {}".format(ds.name))

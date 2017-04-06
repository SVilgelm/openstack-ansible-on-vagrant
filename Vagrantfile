require 'vagrant-reload'

$root_vagrant = File.dirname(File.expand_path(__FILE__))

CONTROLLER_COUNT = ENV['CONTROLLER_COUNT'] || '1'
COMPUTE_COUNT = ENV['COMPUTE_COUNT'] || '0'

OPENSTACK_TMPL = {
    box: 'ubuntu/trusty64',
    memory: 4 * 1024,
    cpus: 2
}

ANSIBLE_TMPL = {
    box: 'ubuntu/trusty64',
    memory: 512,
    cpus: 1,
    role: :ansible
}

nodes = {
    icehouse: {
        ansible: ANSIBLE_TMPL.clone.merge({
                                              branch: 'eol-icehouse',
                                              rpc: true,
                                              patch: 'icehouse.patch'
                                          })
    },

    newton: {
        ansible: ANSIBLE_TMPL.clone.merge({
                                              branch: 'stable/newton',
                                              patch: 'newton.patch',
                                              memory: 5 * 1024,
                                          })
    }
}

IP_MGMT_TMPL = '192.168.%d.%d'
IP_STORAGE_TMPL = '172.29.%d.%d'
IP_TUNNEL_TMPL = '172.30.%d.%d'

INTERFACES = <<-TEXT
auto eth1
iface eth1 inet manual

auto eth2
iface eth2 inet manual

auto eth3
iface eth3 inet manual

auto br-mgmt
iface br-mgmt inet static
    bridge_stp off
    bridge_waitport 0
    bridge_fd 0
    bridge_ports eth1
    address %{ip_mgmt}
    netmask 255.255.0.0

auto br-mgmt:0
allow-hotplug br-mgmt:0
iface br-mgmt:0 inet static
    address %{ip_mgmt_ext}
    netmask 255.255.255.0
    mtu 1450

auto br-mgmt:1
allow-hotplug br-mgmt:1
iface br-mgmt:1 inet static
    address %{ip_mgmt_int}
    netmask 255.255.255.0
    mtu 1450

auto br-storage
iface br-storage inet static
    bridge_stp off
    bridge_waitport 0
    bridge_fd 0
    bridge_ports eth2
    address %{ip_storage}
    netmask 255.255.255.0

auto br-vxlan
iface br-vxlan inet static
    bridge_stp off
    bridge_waitport 0
    bridge_fd 0
    bridge_ports eth3
    address %{ip_tunnel}
    netmask 255.255.255.0

auto br-vlan
iface br-vlan inet manual
    bridge_stp off
    bridge_waitport 0
    bridge_fd 0
    bridge_ports pvlan
TEXT


UC_HOSTS_TMPL = <<-TEXT
  %{name}:
    ip: %{ip}
TEXT

UC_USED_IPS_TMPL = '  - %{ip}'

UC_HOSTS_STORAGE_TMPL = <<-TEXT
  %{name}:
    ip: %{ip}
    container_vars:
      cinder_backends:
        lvm:
          volume_driver: cinder.volume.drivers.lvm.LVMVolumeDriver
          volume_group: cinder-volumes
          volume_backend_name: lvm
        limit_container_types: cinder_volume
      cinder_default_volume_type: lvm
TEXT

USER_CONFIG = <<-TEXT
---
cidr_networks:
  container: %{mgmt_net}/24
  storage: %{storage_net}/24
  tunnel: %{tunnel_net}/24

used_ips:
%{used_ips}

global_overrides:
  internal_lb_vip_address: %{ip_mgmt_int}
  external_lb_vip_address: %{ip_mgmt_ext}
  tunnel_bridge: "br-vxlan"
  management_bridge: "br-mgmt"
  provider_networks:
    - network:
        container_bridge: "br-mgmt"
        container_type: "veth"
        container_interface: "eth1"
        ip_from_q: "container"
        type: "raw"
        group_binds:
          - all_containers
          - hosts
        is_container_address: true
        is_ssh_address: true
    - network:
        container_bridge: "br-vxlan"
        container_type: "veth"
        container_interface: "eth10"
        ip_from_q: "tunnel"
        type: "vxlan"
        range: "1:1000"
        net_name: "vxlan"
        group_binds:
          - neutron_linuxbridge_agent
    - network:
        container_bridge: "br-vlan"
        container_type: "veth"
        container_interface: "eth12"
        host_bind_override: "eth12"
        type: "flat"
        net_name: "flat"
        group_binds:
          - neutron_linuxbridge_agent
    - network:
        container_bridge: "br-vlan"
        container_type: "veth"
        container_interface: "eth11"
        type: "vlan"
        range: "1:1"
        net_name: "vlan"
        group_binds:
          - neutron_linuxbridge_agent
    - network:
        container_bridge: "br-storage"
        container_type: "veth"
        container_interface: "eth2"
        ip_from_q: "storage"
        type: "raw"
        group_binds:
          - glance_api
          - cinder_api
          - cinder_volume
          - nova_compute

shared-infra_hosts:
%{controllers}

repo-infra_hosts:
%{controllers}

os-infra_hosts:
%{controllers}

identity_hosts:
%{controllers}

network_hosts:
%{controllers}

storage-infra_hosts:
%{controllers}

log_hosts:
%{controllers}

haproxy_hosts:
%{controllers}

compute-infra_hosts:
%{controllers}

orchestration_hosts:
%{controllers}

dashboard_hosts:
%{controllers}

network_hosts:
%{controllers}

metering-infra_hosts:
%{controllers}

metering-alarm_hosts:
%{controllers}

metrics_hosts:
%{controllers}

image_hosts:
%{controllers}

storage_hosts:
%{storages}

compute_hosts:
%{computes}

metering-compute_hosts:
%{computes}
TEXT

HOSTNAME_IP_TMPL = <<-TEXT
  "%{name}": {
    "ansible_ssh_host": "%{ip}",
    "container_address": "%{ip}"
  }
TEXT

HOSTNAMES_IPS = <<-TEXT
{
%{hosts}
}
TEXT

USER_VARIABLES = <<-TEXT
---
debug: false

haproxy_keepalived_external_vip_cidr: "%{ip_mgmt_ext}/24"
haproxy_keepalived_internal_vip_cidr: "%{ip_mgmt_int}/24"
haproxy_keepalived_external_interface: br-mgmt:0
haproxy_keepalived_internal_interface: br-mgmt:1

elasticsearch_discovery_minimum_master_nodes: 1

## Galera settings
galera_innodb_buffer_pool_size: 512M
galera_innodb_log_buffer_size: 32M
galera_wsrep_provider_options:
 - { option: "gcache.size", value: "32M" }
TEXT

USER_SECRETS = <<-TEXT
aodh_container_db_password: r00tme
aodh_rabbitmq_password: r00tme
aodh_service_password: r00tme
ceilometer_container_db_password: r00tme
ceilometer_rabbitmq_password: r00tme
ceilometer_service_password: r00tme
ceilometer_telemetry_secret: 523eaa97f165dcf6fd4814de3cc89e1a9da977fb591056e60
cinder_ceph_client_uuid: f0a25eeb-646c-4803-84d5-2141157f337c
cinder_container_mysql_password: r00tme
cinder_profiler_hmac_key: 33303e1552fd9b74b3825c1a
cinder_rabbitmq_password: r00tme
cinder_service_password: r00tme
cinder_v2_service_password: r00tme
container_openstack_password: r00tme
galera_root_password: r00tme
glance_container_mysql_password: r00tme
glance_profiler_hmac_key: 18fdd927d1883d37b24f56527efb7942
glance_rabbitmq_password: r00tme
glance_service_password: r00tme
gnocchi_container_mysql_password: r00tme
gnocchi_service_password: r00tme
haproxy_keepalived_authentication_password: r00tme
haproxy_stats_password: r00tme
heat_auth_encryption_key: 944debc363d579d347e390449763020d
heat_container_mysql_password: r00tme
heat_rabbitmq_password: r00tme
heat_service_password: r00tme
heat_stack_domain_admin_password: r00tme
horizon_container_mysql_password: r00tme
horizon_secret_key: a9100747bc206372b546dca2
ironic_container_mysql_password: r00tme
ironic_rabbitmq_password: r00tme
ironic_service_password: r00tme
ironic_swift_temp_url_secret_key: 6c41210e4b6c53cc85a364cb
keystone_auth_admin_password: r00tme
keystone_auth_admin_token: de2540628af5a09a2c5908224871660d1db5b322c8786e32d50d92b9fe6645e0a1
keystone_container_mysql_password: r00tme
keystone_rabbitmq_password: r00tme
keystone_service_password: r00tme
lxd_trust_password: r00tme
magnum_galera_password: r00tme
magnum_rabbitmq_password: r00tme
magnum_service_password: r00tme
magnum_trustee_password: r00tme
memcached_encryption_key: 8ba2ef1c206a8daf5adee34df7d6f23f
neutron_container_mysql_password: r00tme
neutron_ha_vrrp_auth_password: r00tme
neutron_rabbitmq_password: r00tme
neutron_service_password: r00tme
nova_api_container_mysql_password: r00tme
nova_container_mysql_password: r00tme
nova_ec2_service_password: r00tme
nova_metadata_proxy_secret: 523bf464f5a60301bea545c1ab4291691f1e70d448c
nova_rabbitmq_password: r00tme
nova_s3_service_password: r00tme
nova_service_password: r00tme
nova_v21_service_password: r00tme
nova_v3_service_password: r00tme
rabbitmq_cookie_token: 86280fab869f5e3605cfb1ed38f01fab59d515ca757ff6f0eeb42180a6f6966e1deae
rabbitmq_monitoring_password: r00tme
rally_galera_password: r00tme
sahara_container_mysql_password: r00tme
sahara_rabbitmq_password: r00tme
sahara_service_password: r00tme
swift_container_mysql_password: r00tme
swift_dispersion_password: r00tme
swift_hash_path_prefix: c2b8ce002fd62c30d1ffb6d44710ad27
swift_hash_path_suffix: d51e1b1085ebcfd0448096a1
swift_rabbitmq_telemetry_password: r00tme
swift_service_password: r00tme
TEXT

RPC_USER_VARIABLES = <<-TEXT
cinder_container_mysql_password: r00tme
cinder_service_password: r00tme
cinder_v2_service_password: r00tme
container_openstack_password: r00tme
glance_container_mysql_password: r00tme
glance_default_store: file
glance_notification_driver: noop
glance_service_password: r00tme
glance_swift_store_auth_address: "{{ rackspace_cloud_auth_url }}"
glance_swift_store_container: SomeContainerName
glance_swift_store_endpoint_type: internalURL
glance_swift_store_key: "{{ rackspace_cloud_password }}"
glance_swift_store_region: SomeRegion
glance_swift_store_user: "{{ rackspace_cloud_tenant_id }}:{{ rackspace_cloud_username }}"
heat_auth_encryption_key: 6e8c356a13f235c6f539b017
heat_cfn_service_password: r00tme
heat_container_mysql_password: r00tme
heat_service_password: r00tme
heat_stack_domain_admin_password: r00tme
horizon_container_mysql_password: r00tme
horizon_secret_key: cec02dcd0e9f1921699fba2e
keystone_auth_admin_password: r00tme
keystone_auth_admin_token: 8ef0d53d7530847926dbdcc1fd69a1fd5cdc74d67fc97372ff5af86aef5607ea03412c
keystone_container_mysql_password: r00tme
keystone_service_password: r00tme
kibana_password: r00tme
maas_alarm_local_consecutive_count: 3
maas_alarm_remote_consecutive_count: 1
maas_api_key: "{{ rackspace_cloud_api_key }}"
maas_api_url: "https://monitoring.api.rackspacecloud.com/v1.0/{{ rackspace_cloud_tenant_id }}"
maas_auth_method: r00tme
maas_auth_token: some_token
maas_auth_url: "{{ rackspace_cloud_auth_url }}"
maas_check_period: 60
maas_check_timeout: 30
maas_keystone_password: r00tme
maas_keystone_user: maas
maas_monitoring_zones:
- mzdfw
- mziad
- mzord
- mzlon
- mzhkg
maas_notification_plan: npManaged
maas_rabbitmq_password: r00tme
maas_rabbitmq_user: maas_user
maas_repo_version: 9.0.11
maas_scheme: https
maas_target_alias: public0_v4
maas_username: "{{ rackspace_cloud_username }}"
memcached_encryption_key: f2950ca5530e09e2dbf805acf8140699
mysql_root_password: r00tme
neutron_container_mysql_password: r00tme
neutron_service_password: r00tme
nova_container_mysql_password: r00tme
nova_ec2_service_password: r00tme
nova_metadata_proxy_secret: b01df795509c56fe43
nova_s3_service_password: r00tme
nova_service_password: r00tme
nova_v3_service_password: r00tme
rabbitmq_cookie_token: e1f35cbd7d89fe84c1c4ff97cd50cdf4b0d90d082c94ab6a85552ef01030e209bf67
rabbitmq_password: r00tme
rackspace_cloud_api_key: SomeAPIKey
rackspace_cloud_auth_url: https://identity.api.rackspacecloud.com/v2.0
rackspace_cloud_password: r00tme
rackspace_cloud_tenant_id: SomeTenantID
rackspace_cloud_username: admin
rpc_support_holland_password: cb394812b6d3b2219dfc94d693b15f88
TEXT


RPC_USER_CONFIG = <<-TEXT
---
environment_version: <VERSION>
cidr_networks:
  container: %{mgmt_net}/24
  storage: %{storage_net}/24
  tunnel: %{tunnel_net}/24

used_ips:
%{used_ips}

global_overrides:
  internal_lb_vip_address: %{ip_mgmt_int}
  external_lb_vip_address: %{ip_mgmt_ext}
  tunnel_bridge: "br-vxlan"
  management_bridge: "br-mgmt"
  provider_networks:
    - network:
        container_bridge: "br-mgmt"
        container_interface: "eth1"
        type: "raw"
        ip_from_q: "container"
        group_binds:
          - all_containers
          - hosts
    - network:
        container_bridge: "br-vxlan"
        container_interface: "eth10"
        type: "vxlan"
        ip_from_q: "tunnel"
        range: "1:1000"
        net_name: "vxlan"
        group_binds:
          - neutron_linuxbridge_agent
    - network:
        container_bridge: "br-vlan"
        container_interface: "eth12"
        host_bind_override: "eth12"
        type: "flat"
        net_name: "flat"
        group_binds:
          - neutron_linuxbridge_agent
    - network:
        container_bridge: "br-vlan"
        container_interface: "eth11"
        type: "vlan"
        range: "1:1"
        net_name: "vlan"
        group_binds:
          - neutron_linuxbridge_agent
    - network:
        container_bridge: "br-storage"
        container_interface: "eth2"
        type: "raw"
        ip_from_q: "storage"
        group_binds:
          - glance_api
          - cinder_api
          - cinder_volume
          - nova_compute

infra_hosts:
%{controllers}

haproxy_hosts:
%{controllers}

network_hosts:
%{controllers}

log_hosts:
%{controllers}

storage_hosts:
%{storages}

compute_hosts:
%{computes}
TEXT


nodes.each.with_index(1) do |(name, data), ip_index|
  ip = 2
  data[:ansible][:ip_mgmt] = IP_MGMT_TMPL % [ip_index, ip]
  data[:ansible][:ip_mgmt_int] = IP_MGMT_TMPL % [ip_index, ip + 1]
  data[:ansible][:ip_mgmt_ext] = IP_MGMT_TMPL % [ip_index, ip + 2]
  data[:ansible][:ip_storage] = IP_STORAGE_TMPL % [ip_index, ip]
  data[:ansible][:ip_tunnel] = IP_TUNNEL_TMPL % [ip_index, ip]
  data[:ansible][:hostname] = "#{name}-ansible"
  used_ips = [
      data[:ansible][:ip_mgmt],
      data[:ansible][:ip_mgmt_int],
      data[:ansible][:ip_mgmt_ext],
      data[:ansible][:ip_storage],
      data[:ansible][:ip_tunnel]
  ]
  hosts = {}
  ip_mgmt_int = nil
  ip_mgmt_ext = nil
  [[:controller, CONTROLLER_COUNT.to_i], [:compute, COMPUTE_COUNT.to_i]].each do |host_name_prefix, host_count|
    hosts[host_name_prefix] = {}
    (1..host_count).each.with_index(0) do |index|
      if host_count == 1
        host_name_tmpl = '%s'
      else
        host_name_tmpl = '%s-%s'
      end
      host_name = host_name_tmpl % [host_name_prefix, index]
      data[host_name] = OPENSTACK_TMPL.clone
      ip += 3
      data[host_name][:ip_mgmt] = IP_MGMT_TMPL % [ip_index, ip]
      data[host_name][:ip_mgmt_int] = IP_MGMT_TMPL % [ip_index, ip + 1]
      data[host_name][:ip_mgmt_ext] = IP_MGMT_TMPL % [ip_index, ip + 2]
      data[host_name][:ip_storage] = IP_STORAGE_TMPL % [ip_index, ip]
      data[host_name][:ip_tunnel] = IP_TUNNEL_TMPL % [ip_index, ip]
      data[host_name][:hostname] = "#{name}-#{host_name}"
      data[host_name][:role] = host_name_prefix
      hosts[host_name_prefix][data[host_name][:hostname]] = data[host_name][:ip_mgmt]
      if host_name_prefix == :controller and index == 1
        ip_mgmt_int = data[host_name][:ip_mgmt_int]
        ip_mgmt_ext = data[host_name][:ip_mgmt_ext]
      else
        used_ips.push(data[host_name][:ip_mgmt_int])
        used_ips.push(data[host_name][:ip_mgmt_ext])
      end
    end
  end
  storages = hosts[:controller].map {|cname, cip|
    UC_HOSTS_STORAGE_TMPL % {name: cname, ip: cip}
  }.join("\n")
  controllers = hosts[:controller].map {|cname, cip|
    UC_HOSTS_TMPL % {name: cname, ip: cip}
  }.join("\n")
  if hosts[:compute].empty?
    computes = controllers
  else
    computes = hosts[:compute].map {|cname, cip|
      UC_HOSTS_TMPL % {name: cname, ip: cip}
    }.join("\n")
  end
  used_ips = used_ips.map {|cip| UC_USED_IPS_TMPL % {ip: cip}}.join("\n")

  if data[:ansible][:rpc]
    user_config = RPC_USER_CONFIG
  else
    user_config = USER_CONFIG
    data[:ansible][:hostnames_ips] = HOSTNAMES_IPS % {
        hosts: hosts.map {|_hname, hdata|
          hdata.map {|cname, cip|
            HOSTNAME_IP_TMPL.rstrip % {name: cname, ip: cip}
          }.join(",\n")
        }.join
    }
    data[:ansible][:user_variables] = USER_VARIABLES % {
        ip_mgmt_int: ip_mgmt_int,
        ip_mgmt_ext: ip_mgmt_ext
    }
  end
  data[:ansible][:user_config] = user_config % {
      controllers: controllers,
      storages: storages,
      computes: computes,
      used_ips: used_ips,
      ip_mgmt_int: ip_mgmt_int,
      ip_mgmt_ext: ip_mgmt_ext,
      mgmt_net: IP_MGMT_TMPL % [ip_index, 0],
      storage_net: IP_STORAGE_TMPL % [ip_index, 0],
      tunnel_net: IP_TUNNEL_TMPL % [ip_index, 0]
  }
end

etc_hosts = nodes.map {|_name, hosts|
  hosts.map {|_hname, hdata|
    [hdata[:ip_mgmt], hdata[:hostname]].join(' ')
  }.join("\n")
}.join("\n")

$keys = nil

def get_keys
  if $keys
    return $keys
  end
  prv = File.join($root_vagrant, '.vagrant', 'cloud_id_rsa')
  pub = File.join($root_vagrant, '.vagrant', 'cloud_id_rsa.pub')
  unless File.exists?(prv)
    %x(cat /dev/zero | ssh-keygen -f #{prv} -q -C cloud -P "" -N "")
  end
  $keys = {
      prv: File.read(prv),
      pub: File.readlines(pub).first.strip
  }
end


Vagrant.configure('2') do |config|
  nodes.each do |version, hosts|
    hosts.each do |_hname, data|
      config.vm.define data[:hostname] do |this|
        this.vm.box = data[:box]
        this.vm.hostname = data[:hostname]
        this.vm.provision 'shell' do |s|
          s.privileged = true
          s.inline = <<-SCRIPT
            apt-get update 
            apt-get -y dist-upgrade
          SCRIPT
        end
        this.vm.provision :reload

        this.vm.network 'private_network',
                        ip: data[:ip_mgmt],
                        netmask: '255.255.0.0',
                        auto_config: false
        this.vm.network 'private_network',
                        ip: data[:ip_storage],
                        netmask: '255.255.255.0',
                        auto_config: false
        this.vm.network 'private_network',
                        ip: data[:ip_tunnel],
                        netmask: '255.255.255.0',
                        auto_config: false

        this.vm.provision 'shell' do |s|
          keys = get_keys
          interfaces = INTERFACES % {
              ip_mgmt: data[:ip_mgmt],
              ip_mgmt_int: data[:ip_mgmt_int],
              ip_mgmt_ext: data[:ip_mgmt_ext],
              ip_storage: data[:ip_storage],
              ip_tunnel: data[:ip_tunnel]
          }
          s.privileged = true
          s.inline = <<-SCRIPT
            apt-get install -y aptitude bridge-utils ntp ntpdate
            echo '#{etc_hosts}' >> /etc/hosts
            echo '#{keys[:prv]}' > /root/.ssh/id_rsa
            echo '#{keys[:pub]}' > /root/.ssh/id_rsa.pub
            echo '#{keys[:pub]}' >> /root/.ssh/authorized_keys
            chmod 0600 /root/.ssh/id_rsa
            echo '#{interfaces}' >> /etc/network/interfaces
            ifup eth1 eth2 eth3 br-mgmt br-storage br-vxlan br-vlan br-mgmt:0 br-mgmt:1
          SCRIPT
        end

        if data[:role] == :ansible
          this.vm.provision 'shell' do |s|
            ntp_ip = IP_MGMT_TMPL % [data[:ip_mgmt].split('.')[2], 255]
            s.privileged = true
            s.inline = <<-SCRIPT
              apt-get install -y build-essential git python-dev libssl-dev libffi-dev
              echo 'broadcast #{ntp_ip}' >> /etc/ntp.conf
              service ntp restart
              git clone https://git.openstack.org/openstack/openstack-ansible /opt/openstack-ansible
              cd /opt/openstack-ansible
              git checkout #{data[:branch]}
              curl https://bootstrap.pypa.io/get-pip.py | python
              grep -v pip /opt/openstack-ansible/requirements.txt > /tmp/requirements.txt 
              pip install -r /tmp/requirements.txt
              rm /tmp/requirements.txt
              scripts/bootstrap-ansible.sh
            SCRIPT
          end
          if data[:patch]
            this.vm.provision 'file', source: data[:patch], destination: '/tmp/openstack-ansible.patch'
            this.vm.provision 'shell' do |s|
              s.privileged = true
              s.inline = <<-SCRIPT
                cd /opt/openstack-ansible
                git apply /tmp/openstack-ansible.patch
                rm /tmp/openstack-ansible.patch
              SCRIPT
            end
          end
          this.vm.provision 'shell' do |s|
            s.privileged = true
            if data[:rpc]
              s.inline = <<-SCRIPT
                  cp -R /opt/openstack-ansible/etc/rpc_deploy /etc/
                  echo '#{RPC_USER_VARIABLES}' > /etc/rpc_deploy/user_variables.yml
                  echo '#{data[:user_config]}' > /etc/rpc_deploy/rpc_user_config.yml
                  VERSION=`md5sum /etc/rpc_deploy/rpc_environment.yml | awk -F' ' '{print $1}'`
                  sed -i -e "s/<VERSION>/${VERSION}/g" /etc/rpc_deploy/rpc_user_config.yml             
                  cd /opt/openstack-ansible/rpc_deployment
                  openstack-ansible playbooks/setup/host-setup.yml
                  sleep 10
                  openstack-ansible playbooks/infrastructure/haproxy-install.yml
                  openstack-ansible playbooks/infrastructure/infrastructure-setup.yml
                  openstack-ansible playbooks/openstack/openstack-setup.yml
              SCRIPT
            else
              s.inline = <<-SCRIPT
                  cp -R /opt/openstack-ansible/etc/openstack_deploy /etc/
                  echo '#{data[:user_config]}' > /etc/openstack_deploy/openstack_user_config.yml
                  echo '#{data[:hostnames_ips]}' > /etc/openstack_deploy/openstack_hostnames_ips.yml
                  echo '#{data[:user_variables]}' > /etc/openstack_deploy/user_variables.yml
                  echo '#{USER_SECRETS}' > /etc/openstack_deploy/user_secrets.yml
                  cd /opt/openstack-ansible/playbooks
                  openstack-ansible setup-everything.yml
              SCRIPT
            end
          end
        else
          this.vm.provision 'shell' do |s|
            s.privileged = true
            s.inline = <<-SCRIPT
              apt-get install -y debootstrap ifenslave ifenslave-2.6 lsof lvm2 tcpdump vlan
              echo 'disable auth' >> /etc/ntp.conf
              echo 'broadcastclient' >> /etc/ntp.conf
              service ntp restart
              echo 'bonding' >> /etc/modules
              echo '8021q' >> /etc/modules

              fallocate -l 4G /swapfile
              chmod 600 /swapfile
              mkswap /swapfile
              swapon /swapfile
              echo '/swapfile none swap defaults 0 0' >> /etc/fstab
            SCRIPT
          end
          if data[:role] == :controller
            this.vm.provision 'shell' do |s|
              s.privileged = true
              s.inline = <<-SCRIPT
                parted /dev/sdb mklabel msdos
                parted -a optimal /dev/sdb mkpart primary ext4 0% 100%
                mkfs.ext4 -L DATA /dev/sdb1
                pvcreate --metadatasize 2048 /dev/sdb1
                vgcreate cinder-volumes /dev/sdb1
              SCRIPT
            end
          end
        end

        this.vm.provider 'virtualbox' do |v|
          v.memory = data[:memory]
          v.cpus = data[:cpus]
          v.customize ['modifyvm', :id, '--cpuexecutioncap', '90']
          v.customize ['modifyvm', :id, '--nicpromisc2', 'allow-all']
          v.customize ['modifyvm', :id, '--nicpromisc3', 'allow-all']
          v.customize ['modifyvm', :id, '--nicpromisc4', 'allow-all']
          if data[:role] == :controller
            disk = File.join($root_vagrant, '.vagrant', "#{data[:hostname]}.vdi")
            unless File.exist?(disk)
              %x(VBoxManage createhd --filename "#{disk}" --size #{20 * 1024} --format VDI)
            end
            v.customize ['storageattach', :id, '--storagectl', 'SATAController', '--port', 1, '--device', 0, '--type', 'hdd', '--medium', disk]
          end
        end
      end
    end
  end
end

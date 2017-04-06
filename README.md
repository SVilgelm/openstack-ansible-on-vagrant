# openstack-ansible-on-vagrant
Vagrantfile for deploying OpenStack clouds using openstack-ansible


# Usage
***All in one***

```
$ vagrant status
Current machine states:

icehouse-ansible          not created (virtualbox)
icehouse-controller       not created (virtualbox)
newton-ansible            not created (virtualbox)
newton-controller         not created (virtualbox)
```


***HA***

```
$ export COMPUTE_COUNT=5
$ export CONTROLLER_COUNT=3
$ vagrant status
Current machine states:

icehouse-ansible          not created (virtualbox)
icehouse-controller-1     not created (virtualbox)
icehouse-controller-2     not created (virtualbox)
icehouse-controller-3     not created (virtualbox)
icehouse-compute-1        not created (virtualbox)
icehouse-compute-2        not created (virtualbox)
icehouse-compute-3        not created (virtualbox)
icehouse-compute-4        not created (virtualbox)
icehouse-compute-5        not created (virtualbox)
newton-ansible            not created (virtualbox)
newton-controller-1       not created (virtualbox)
newton-controller-2       not created (virtualbox)
newton-controller-3       not created (virtualbox)
newton-compute-1          not created (virtualbox)
newton-compute-2          not created (virtualbox)
newton-compute-3          not created (virtualbox)
newton-compute-4          not created (virtualbox)
newton-compute-5          not created (virtualbox)
```
<img src="https://www.radware.com/RadwareSite/MediaLibraries/Images/logo.svg" width="300px">

# radware-ansible
The radware-ansible project provides an Ansible collection for managing and automating your Radware devices. It consists of a set of modules and roles for performing tasks related to Radware devices configuration.

## Requirements
- Ansible >= 2.9
- Python >= 3.6
- alteon-sdk python package

## Installation
```
# ansible-galaxy collection install radware.radware_modules
```

## Example Usage
Once the collection is installed, you can use it in a playbook by specifying the full namespace path to the module, plugin and/or role.

```
- hosts: localhost

  tasks:
  - name: alteon configuration command
    radware.radware_modules.alteon_config_l2_vlan:
      provider: 
        server: 192.168.1.1
        user: admin
        password: admin
        validate_certs: no
        https_port: 443
        ssh_port: 22
        timeout: 5
      state: present
      parameters:
        index: 45
        state: enabled
        name: test_vlan
        source_mac_learning: enabled
        ports:
          - 1
          - 2
```

## Copyright

Copyright 2020 Radware LTD

## License
GNU General Public License v3.0

See [COPYING](COPYING) to see the full text.

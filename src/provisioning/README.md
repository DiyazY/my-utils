# Provisioning
This directory contains the provisioning scripts for setting up the development environment.

## Prerequisites
- Ansible
- Python 3.8 or higher

## Installation
Run `ansible-playbook ./src/provisioning/playbooks/install-software.yaml` to install the required software.
This will install the following software:
- git
- pyenv
- iterm2
- vscode
- colima
- nvm
- dotnet-sdk
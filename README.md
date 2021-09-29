# AWS Host Plugin for HashiCorp Boundary

This repo contains a Host-type plugin for [HashiCorp
Boundary](https://www.boundaryproject.io/) allowing dynamically sourcing hosts
from Amazon EC2.

Host sets created with this plugin define filters which select and group like
instances within AWS; these host sets can in turn be added to targets within
Boundary as host sources.

At creation or update of a host catalog of this type, configuration of the
plugin is performed via the attribute/secret values passed to the create or
update calls actions. These values are input as JSON objects; the expected types
are indicated below with the valid fields.

This plugin is currently in heavy development! A more formal README and
documentation will follow soon.

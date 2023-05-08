# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [1.1.1](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/compare/v1.1.0...v1.1.1) (2023-05-08)

## 1.0.0 (2023-04-03)

OpenSourced `sealpack` as of today.

### Features

* create images directly from ECR layers
* local containerd importing
* code and container signing
* combined signature verification
* json logger
* provide contents as config file
* allow to create public file (w/o encryption)
* sealing and unsealing through streaming
* support multiple types of keys

### Bug Fixes

* changed default encryption algorithm
* fixed upgrade package unsealing
* verify AWS session before every AWS action

# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## 1.0.0 (2023-04-03)

OpenSourced `sealpack` as of today.

### Features

* create images directly from ECR layers ([9600e31](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/9600e315fcc3ea7f8239d791e91cf7e2e3faccfa))
* local containerd importing ([fd8a675](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/fd8a675071f6bd24e8f58668f0a6e02027b2358e))
* code and container signing ([396d000](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/396d000481e88acabdeb899e6b88f84910836b3c))
* combined signature verification ([f7b062b](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/f7b062b40cee28cd47b58a85e81152301ba73b69))
* json logger ([2c8de8a](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/2c8de8a7bb0fc06308bbca321a1551582af64749))
* provide contents as config file ([f4870f3](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/f4870f3bb78c22170bb031bdcedba927f14d1916))
* allow to create public file (w/o encryption) ([cebfd3b](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/cebfd3b8c27f4b1f3a8c3ab1d2f8e0cd1e7fccca))
* sealing and unsealing through streaming ([d325672](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/d32567272370d0e6c7b89743cc4790c4237e868d))
* support multiple types of keys ([e138fca](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/e138fca00af250b5dec4749fa19670c653c99448))

### Bug Fixes

* changed default encryption algorithm ([d7e4899](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/d7e4899b3dc81ad096cf0b0a8e9de2f2d5e85c48))
* fixed upgrade package unsealing ([ddadf90](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/ddadf9036c70bc79f669a9f8db265e6a59021ae0))
* verify AWS session before every AWS action ([0d955e4](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/0d955e41aadd894191d8b39870350b3b1cf9b442))

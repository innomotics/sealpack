# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## 1.0.0 (2023-04-03)


### Features

* allow unsealing ([6b134e5](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/6b134e50f6a207fb26f89a70319fc0e368b7e302))
* build with correct ([e6a46bb](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/e6a46bbb5834e4f4c1f69c92d7a41822660fe9b7))
* changed unpacking from byte-slice copying to reader usage ([98fbd81](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/98fbd81e6b4e7b9099f106b055c04f85ad106c5d))
* create images directly from ECR layers ([19b8fbc](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/19b8fbca8b282477f17361e73457f3e097fe56d4))
* create images directly from ECR layers ([9600e31](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/9600e315fcc3ea7f8239d791e91cf7e2e3faccfa))
* finished containerd importing ([fd8a675](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/fd8a675071f6bd24e8f58668f0a6e02027b2358e))
* Finished core part of signing ([396d000](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/396d000481e88acabdeb899e6b88f84910836b3c))
* Finished sealing blindly ([532d64c](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/532d64ce5ccba83bd44255a676b44be104115448))
* finished signature verification ([f7b062b](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/f7b062b40cee28cd47b58a85e81152301ba73b69))
* first working version ([7b2513d](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/7b2513d8d70b91b9235a3f24aa0b918019a790d8))
* first working version ([3bdeffe](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/3bdeffeca91029aa78fb1b236c4c94f0a6ca7b00))
* fix sealing algorithm and allow for parsing+inspection ([1f3001a](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/1f3001aceb96fa746a88097c3b05d1fb84ae2f1e))
* **log:** add json logger ([2c8de8a](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/2c8de8a7bb0fc06308bbca321a1551582af64749))
* make lambda runnable again ([7c247d0](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/7c247d0032d812236ac8dd03de8b9836021596bc))
* parse application config ([f4870f3](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/f4870f3bb78c22170bb031bdcedba927f14d1916))
* possiblity to create public file (w/o encryption) ([cebfd3b](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/cebfd3b8c27f4b1f3a8c3ab1d2f8e0cd1e7fccca))
* preparation for working USB upgrade ([8dcf53f](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/8dcf53f0a69626827b0fee540edbc7ee4eab20e2))
* Sealing running now ([ec7e09c](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/ec7e09ca68d3835e27ddce80c0b81170bbe3679c))
* sealing through streaming works almost; key decryption still buggy. ([d325672](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/d32567272370d0e6c7b89743cc4790c4237e868d))
* sealing through streaming works almost; key decryption still buggy. ([7d8b9ee](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/7d8b9ee0d21f8b755314a5ec18927afaaeb936ea))
* sealing through streaming works almost; key decryption still buggy. ([f910de6](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/f910de6e3d2eb7f597b2a3f4b67175da686db362))
* started cleanup ([2520169](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/2520169899638c45cf01fb7319ca9277a758fdd7))
* support multiple types of keys ([e138fca](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/e138fca00af250b5dec4749fa19670c653c99448))
* support multiple types of keys ([eccf493](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/eccf4930740a6744c4a4c1e7264ac9c1aeb656c7))


### Bug Fixes

* changed default encryption algorithm ([62c5ebb](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/62c5ebb03c29dcc242be019bed45ac6b82e6fb7f))
* changed default encryption algorithm ([9fdf737](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/9fdf737f82ae07a387dba121f3392badae02b3c4))
* changed default encryption algorithm ([3dbdf8e](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/3dbdf8ea87aa02d51417871b56f2ed7d7daedd86))
* changed default encryption algorithm ([d7e4899](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/d7e4899b3dc81ad096cf0b0a8e9de2f2d5e85c48))
* fixed upgrade package unsealing ([ddadf90](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/ddadf9036c70bc79f669a9f8db265e6a59021ae0))
* verifyx AWS session before every AWS action ([0d955e4](https://code.siemens.com/sidrive-iq/teams/team-ecs/suse-edge/tools/sealpack/commit/0d955e41aadd894191d8b39870350b3b1cf9b442))

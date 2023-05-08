# Request for a new public repository on [github.com/innomotics](https://github.com/innomotics)

<!--
  Projects in the Innomotics organization on GitHub represent our company in the Open Source community.
  They therefore need to be of high quality and provide clear value to the outside world.

  The topics below might seem overwhelming at first, but they cover everything the community expects from professional Open Source projects.

  If you're unsure about anything let's discuss in the Merge Request and we'll work it out together!
-->

## Basic information

Purpose of the project: provide an easy-to-use CLI tool to sign, compress and encrypt files and containers for specific receivers

Differentiating factor from existing open source projects: Single CLI binary based on well-established standards

Why was contributing to an existing project not viable: No project alike existed. All used projects are used as part of our contribution

URL of repository to be pushed (should be accessible for internal review): https://github.com/innomotics/sealpack

## Approval

* [ ] Your organization [agrees on making this component *Open Source*](https://wiki.siemens.com/x/E6n-Bg) and an approval email is attached to this Merge Request. (This includes a mandatory check for IPR issues.)
* [x] The funding and staffing of the project is clarified for more than the current fiscal year. Some topics to consider:
    * Community interaction: reasonable response time assured (for issues, merge requests etc.)
    * Dependency management: consumed third-party libraries are kept up-to-date, especially with respect to security patches
    * (v) _@mathias.haimerl opted in to keep supporting the project long-term, even post-employment_.
    * (v) _Created a mailing list sealpack@googlegropus.com_

## Maintainer readiness

* [x] Maintainers are familiar with Git and have experience contributing to or maintaining Open or Inner Source Software. Experience should be visible on GitHub and/or code.siemens.com profiles or explicitely listed in this Merge Request.
* [x] Maintainers are listed in a [`CODEOWNERS` file](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners).
* [x] You have considered applying as a [Social Coding Ambassador](https://code.siemens.io/docs/_ambassadors)
* [x] You know the Linux Foundation's [Core Infrastructure best practices](https://bestpractices.coreinfrastructure.org), see e.g. [Embedded Multicore Building Blocks](https://bestpractices.coreinfrastructure.org/projects/654) and plan to apply them.
* [x] You joined [@Open Source and Open Standards](https://www.yammer.com/siemenscrosscollaboration/#/threads/inGroup?type=in_group&feedId=2884550656) on Yammer.

## Repository tidiness

* [x] Results of [repolinter](https://github.com/todogroup/repolinter) run are available and attached to this Merge Request.
  * (v) _Integrated repolinter with custom config in pipeline_
* [x] There are no credentials in the repository (use [`gitleaks`](https://github.com/zricethezav/gitleaks) or similar tools to double-check).
  * (v) _Integrated gitleaks with custom config in pipeline for continuous monitoring_
* [x] The Git history of the repository is clean, e.g. no orphaned branches, committed binaries or temporary commits.
* You have verified that your code **does not contain** any of the following information:
    * [ ] Siemens department identifiers (org codes)
      * LDA is still named, because "lda-portal" is the name of the organization
    * [x] Names of Siemens products or projects, or the corresponding release numbers and their release dates
    * [x] Configuration information for real IT environments, such as server names, IP addresses, login information, passwords or private keys.
    * [x] Names of Siemens employees other than the authors
    * [x] Inappropriate language
    * [x] Any expressions like "stolen from", "copied from", or similar. A contribution is a serious matter, and no
      place for jokes. If you need to provide information such as "derived from", make sure to also provide the license
      information of the work that your contribution is derived from.

## Workflow

* [x] You do not work directly on the main branch; it is protected
* [x] You use the [merge request workflow](https://code.siemens.com/help/user/project/merge_requests/index.md) and [Conventional Changelog](https://wiki.siemens.com/display/en/Conventional+Changelog)
* [x] `CHANGELOG.md` available and auto generated
* [x] You use CI/CD, e.g. using GitHub actions

## Documentation

You use [Markdown](https://en.wikipedia.org/wiki/Markdown) to nicely integrate your docs on [github.com/siemens](https://github.com/siemens).

* [x] `README.md` describes the project, and how to use it.
* [x] All required documentation is available in the repository itself
    * there are no links to Siemens-internal resources, e.g. `code.siemens.com` or `wiki.siemens.com`
    * documentation is written in Markdown (or a similar markup language)
* [x] `CONTRIBUTING.md` is available, see [GitHub documentation](https://help.github.com/articles/setting-guidelines-for-repository-contributors/). For examples,
  see [Jailhouse](https://github.com/siemens/jailhouse/blob/main/CONTRIBUTING.md) and [code.siemens.com](https://code.siemens.com/siemens/code/blob/main/CONTRIBUTING.md).

## Licensing and copyright

Make sure your project is compliant with the [REUSE](https://reuse.software/practices/) practices. See [Licensing for
Open Source contributions](https://code.siemens.com/siemens/code/blob/main/docs/opensource/licensing.md) for details
and guidance.

* [x] You have chosen a standard [Open Source license](https://opensource.org/licenses) in coordination with the budget owner, according to the projects goals and context.
* [x] You have checked that there are no license incompatibilities in your code.
  * Did an in-depth license clearing based on a generated SBOM
* [x] Any third-party components that are published along with the project have gone through a clearing process.
* [x] You provide the full text of the license in the root directory of your project, e.g. in a file named `LICENSE`.
* [x] You provide the copyright information in the root directory of your project, e.g. in a file named `COPYING` or in the `README`.
* [x] Source files contain correct and complete information regarding licensing (using the [SPDX](https://spdx.org/) license identifiers) and copyright.
* [x] You have NOT removed copyright, licensing information or license texts from files you have modified.

Example of copyright and license notice:

  ```txt
  Copyright YEAR Innomotics GmbH
  SPDX-License-Identifier: Apache-2.0
  ```

> The [reuse developers tools](https://github.com/fsfe/reuse-tool) can help you automatically create and maintain compliant license and copyright information into your Open Source project.

## code-ops maintainer tasks

* [ ] Run `deploy-production` manual job if `check-production` is green after merge

/label ~new-github-repo


# contentctl
> ## The Future of contentctl
> We are shifting future investment from contentctl to Detection Studio as we work to bring this functionality into Splunk as an officially supported capability. This repository will remain publicly available for reference, but we are no longer accepting new pull requests or feature requests. Going forward, continued use of contentctl may require customer-managed customization to support specific environments and requirements. 

<p align="center">
<img src="https://raw.githubusercontent.com/splunk/contentctl/refs/heads/main/docs/contentctl_logo_white.png" title="In case you're wondering, it's a capybara" alt="the logo for the contentctl project, which depicts a doodled 4 legged animal that is supposed to represent a capybara, with the name of the project below it" width="250" height="250"></p>



## What is contentctl?
`contentctl` is a tool developed by the Splunk Threat Research Team to help with managing the content living in [splunk/security_content](https://github.com/splunk/security_content) and producing the Enterprise Security Content Update app for Splunk. While its development is largely driven by STRT's needs, it has been somewhat genericized and can be used by customers and partners to package their own content. Simply put, `contentctl` is the workhorse that packages detections, macros, lookups, dashboards into a Splunk app that you can use, and that understands the YAML structure and project layout we've selected to keep development clean.

## Quick Start Guide
Check out our [User Guide](docs/UserGuide.md) to get started!

## Content Testing
Read more about how `contentctl` can help test and validate your content in a real Splunk instance [here](docs/ContentTestingGuide.md).

## Sample CICD Workflows
Already using `contentctl`, or looking to get started with it already configured in GitHub Actions? [Our guide](docs/Sample_CICD_Templates.md) includes workflows to help you build and test your app.

## Ecosystem
| Project               | Description                                             |
| --------------------- | ------------------------------------------------------- |
| [Splunk Security Content](https://github.com/splunk/security_content)          | Splunk Threat Research Team's Content included in the [Enterprise Security Content Update App (ESCU)](https://splunkbase.splunk.com/app/3449)|
| [Splunk Attack Range](https://github.com/splunk/attack_range)          | Easily deploy a preconfigured Splunk Environment locally or on AWS containing a Splunk Instance, Windows and Linux Machines, and Attacker Tools like Kali Linux.  Automatically simulate attacks or run your own|
| [Splunk Attack Data](https://github.com/splunk/attack_data)          | Repository of Attack Simulation Data for writing and Testing Detections|                         |
| [Splunk contentctl](https://github.com/splunk/contentctl)          | Generate, validate, build, test, and deploy custom Security Content|
| [SigmaHQ Sigma Rules](https://github.com/SigmaHQ/sigma) | Official Repository for Sigma Rules. These rules are an excellent starting point for new content. |
| [PurpleSharp Attack Simulation](https://github.com/mvelazc0/PurpleSharp) | Open source adversary simulation tool for Windows Active Directory environments (integrated into Attack Range)|
| [Red Canary Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)          | Library of attack simulations mapped to the MITRE ATT&CK® framework (integrated into Attack Range)|

## License
Copyright 2023 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

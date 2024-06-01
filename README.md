<!--
 Copyright (C) 2023 Sebastian Kawelke, l3montree UG (haftungsbeschraenkt)
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.
 
 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
-->

<!-- Improved compatibility of back to top link: See: https://github.com/othneildrew/Best-README-Template/pull/73 -->
<a name="readme-top"></a>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://flawfix.dev">
    <img src="images/logo_horizontal.svg" alt="FlawFix by L3montree Logo" width="240" height="80">
  </a>

  <h3 align="center">FlawFix - Vulnerability Management - Backend</h3>

  <p align="center">
    Manage your CVEs seamlessly, Integrate your Vulnerability Scanners, Documentation made easy, Compliance to security Frameworks
    <br />
    <a href="https://flawfix.dev/docs/getting-started"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/l3montree-dev/flawfix/issues">Report Bug</a>
    ·
    <a href="https://github.com/l3montree-dev/flawfix/issues">Request Feature</a>
  </p>
</div>

<p align="center">
   <a href="https://www.bestpractices.dev/projects/8928"><img src="https://www.bestpractices.dev/projects/8928/badge" alt="OpenSSF Badge"></a>
   <a href="https://github.com/calcom/cal.com/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPLv3-purple" alt="License"></a>
   <a href="https://github.com/l3montree-dev/flawfix/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22"><img src="https://img.shields.io/badge/Help%20Wanted-Contribute-blue"></a>
</p>


<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="##code-of-conduct">Code of Conduct</a></li>
    <li><a href="#license">License</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->
## Mission

FlawFix is built by developers, for developers, aiming to simplify the complex world of vulnerability management. Our goal is to integrate security seamlessly into the software development lifecycle, ensuring that security practices are accessible and efficient for everyone, regardless of their security expertise.

### The problem we solve

Identifying and managing software vulnerabilities is an increasingly critical challenge. Developers often face security issues without the proper training or tools that fit into their everyday workflows. FlawFix is a developer-centered software designed to provide simple, modern solutions for vulnerability detection and management, compliant with common security frameworks.

In 2023 alone, cyberattacks caused approximately 206 billion euros in damage only in Germany. Many of these attacks exploited software vulnerabilities. With agile and DevOps methodologies becoming standard, the need for integrating security into the development process has never been greater. We aim to fill this gap with FlawFix, offering a seamless integration of vulnerability management into development workflows.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Key Features

- **Developer-Centric Integration:** FlawFix fits naturally into your existing CI/CD workflows, reducing friction and enhancing productivity.
- **Automated Security Monitoring:** Continuous monitoring using Software Bill of Materials (SBOMs) to keep your projects secure.
- **Risk Assessment:** Automatically assesses and prioritizes risks to help you address the most critical vulnerabilities first — no really, we do this pragmatically and automate where possible! (Our base: CVSS, exploitdb, EPSS)
- **Compliance:** Ensures your projects meet security standards like ISO/IEC 27001 and PCI-DSS.
- **Security and confidentiality:** We prioritize the security of this software! In an expansion stage and in cooperation with research institutions, we want to make confidential data processing usable for the secure handling of sensitive information (confidential computing).

<!-- USAGE EXAMPLES -->
## Local Quickstart

1. Clone the repo

   ```sh
   git clone git@github.com:l3montree-dev/flawfix.git
    ```

2. Install Go, Docker & Docker-Compose
3. Copy the `.env.example` file to `.env` and adjust the values to your needs
4. Run the following command to start the necessary services

   ```sh
   docker-compose up
   ```

5. Start the application by running the following command

   ```sh
   make
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTRIBUTING -->
## Contributing

We welcome contributions! Please read our [contribution guide](./CONTRIBUTING.md) if you would like to report a bug, ask a question, write issues, or help us with coding. All help is appreciated!

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- Code of Conduct -->
## Code of Conduct

Help us keep FlawFix open and inclusive. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Built With

FlawFix is divided into two projects: A frontend (FlawFix Web) and a backend (FlawFix Backend). 

**Backend (this project):**
* [![Go][go.dev]][go-url]

**Frontend:**
* Please refer to: [FlawFix-Web on Github](https://github.com/l3montree-dev/flawfix-web)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- LICENSE -->
## License

Distributed under the AGPL-3.0-or-later License. See [`LICENSE.txt`](LICENSE.txt) for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[go.dev]: https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white
[go-url]: https://go.dev

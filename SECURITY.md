# Security Policy

## Versions

The most recent patches and the most current software is published on the `:unstable` tag of the container image. Because of this, the latest security updates will be published first on this rolling tag. For production use, there will be a regular patch or minor release with a versioned container image tag. 

Older tags need manual updating, as we do not usually release an updated image for an existing tag; this will only be done in case of _severe_ vulnerabilities.

| Image Tags      | Latest Packages & Patches |
|-----------------|:-------------------------:|
| `:unstable`     | :white_check_mark:        |
| not `:unstable` | :x:                       |


## Reporting a Vulnerability

When reporting a vulnerability, you can use GitHub's "Private Vulnerability Reporting". Just navigate to the [Report a vulnerability](https://github.com/l3montree-dev/flawfix/security) page. This way, maintainers will privately notified first. Afterwards, in a best-case scenario, if the vulnerability is fixed, the report will be made public.

*Text based on: [DMS](https://github.com/docker-mailserver/docker-mailserver/blob/master/SECURITY.md)*
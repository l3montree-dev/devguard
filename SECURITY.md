# Security Policy

## Versions

The most recent patches and the most current software is published on the `:unstable` tag of the container image. Because of this, the latest security updates will be published first on this rolling tag. For production use, there will be a regular patch or minor release with a versioned container image tag. 

Older tags need manual updating, as we do not usually release an updated image for an existing tag; this will only be done in case of _severe_ vulnerabilities.

| Image Tags      | Latest Packages & Patches |
|-----------------|:-------------------------:|
| `:unstable`     | :white_check_mark:        |
| not `:unstable` | :x:                       |


## Reporting a Vulnerability

When reporting a vulnerability, you can use GitHub's "Private Vulnerability Reporting". Just navigate to the [Report a vulnerability](https://github.com/l3montree-dev/flawfix/security/advisories/new) page. This way, maintainers will privately notified first. Afterwards, in a best-case scenario, if the vulnerability is fixed, the report will be made public.

Alternatively, you can report a vulnerability or anomaly to the L3montree development team. This initiates the procedure of a Coordinated Vulnerability Disclosure. The team will then endeavour to develop security patches within a week if possible. The vulnerability is then made public in the course of their publication. If you wish, you can also be published as a reporter.

```asciiarmor
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Contact: mailto:developer@l3montree.com
Expires: 2026-12-31T23:00:00.000Z
Encryption: https://l3montree.com/developer@l3montree.com-0xA71508222B6168D5-pub.asc
Preferred-Languages: en, de
Canonical: https://l3montree.com/.well-known/security.txt
-----BEGIN PGP SIGNATURE-----

iQJMBAEBCAA2FiEEg2Cvc8K1bPr9yFM3pxUIIithaNUFAmWz2RIYHGRldmVsb3Bl
ckBsM21vbnRyZWUuY29tAAoJEKcVCCIrYWjVFeIQALn6RPOJaUhnIG7i1woTq6fq
Xi1RrHwT6x0m0+RfERuYyOklUnx131VFrfa/axRri6v+gajFTcNrCEObZyjp2KTC
CvTGUKM26w1wbrz1pgmPc7NZV/M/XTzV+yr4Qhh237v0YxVRKkeKuUAJpeVJ8OPq
TcJoZrRRmIZ1stLk6IpNH/GBmcjcQRlOZQK+oIOlRVRR8j66Ko3M6hkCO3AUYw6e
bhjVJ4WbaWSVhT853QAsgZy9hhI8Ug9aeR5/ytC5C1ZWu6D/MiURJLYfRLS9OeKQ
Za3Jm1R/1iizNfQ4bMke/+zbAe2Qy5D53r+hMX/hOkBrbmzDtxqYBaEkRMy9bTcY
18O+81/tqhEfVcfLnXnMuqFqL1v6SG3oH2mhn5GWzdE9ihKhSJiqK/apdmJccTa2
64Pwvbn96fNOxO5rVSJH+nRVedmGnkKRKkTKio/DNNy4JdUzM5HvYgc2BOxGHcSp
K1+JJPx+LwTZ0b+M5kpJ0OImPdziSYa6uLM30tZ97LapIM70KIJD9yKOLVykAo8J
di+uAwE2HG9DZx+2QR9qhypm6NZflVHXPfNdKSVleCb0H1iO4jRtAlwaiuqcoVuW
DZ3ISTStXalb96Xbf3A5cVY/IMqeXaTZ/hwcK3icNvokSVgG9EqhvLVSZmrt6XJb
2B2IVNof3KEgRt3kQsvg
=FPOy
-----END PGP SIGNATURE-----
```

*Text based on: [DMS](https://github.com/docker-mailserver/docker-mailserver/blob/master/SECURITY.md)*
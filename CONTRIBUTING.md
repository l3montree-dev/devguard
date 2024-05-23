# Contributing to FlawFix

## Code of Conduct

The FlawFix project has a [Code of Conduct](./CODE_OF_CONDUCT.md) to which all contributors must adhere.

## Overview

Feedback and contributions are very welcome!

Here's help on how to make contributions, divided into the following sections:

* general information,
* [vulnerability reporting](#vulnerability-reporting-security-issues),
* documentation changes,
* code changes,
* reuse (third-party components)

## General information

For specific proposals, please provide them as
[pull requests](https://github.com/l3montree-dev/flawfix/pulls)
or
[issues](https://github.com/l3montree-dev/flawfix/issues)
via our
[GitHub site](https://github.com/l3montree-dev/flawfix).

We use GitHub. You may find
[GitHub CLI (`gh`)](https://cli.github.com/)
helpful if you're using the command line.
It supports commands like `gh auth login` (login) and
`gh pr create` (create a new pull request
with the current branch).

The "docs/" directory has information you may find helpful, for example:

* [motivation-objectives.md](./docs/motivation-objectives.md) provides an overview of the project motivation and objectives.

The [INSTALL.md](docs/INSTALL.md) file explains how to install the program
locally (highly recommended if you're going to make code changes).

If you're new to the project (or FLOSS in general), the
[Good first issues](https://github.com/l3montree-dev/flawfix/labels/good%20first%20issue) are smaller tasks that may typically take 1-3 days.
You are welcome aboard!

See [CODE OF CONDUCT](./CODE_OF_CONDUCT.md) for our code of conduct;
in short, "Be excellent to each other".

### Pull requests and different branches recommended

Pull requests are preferred, since they are specific.
For more about how to create a pull request, see
<https://help.github.com/articles/using-pull-requests/>.

We recommend creating different branches for different (logical)
changes, and creating a pull request when you're done into the main branch.
See the GitHub documentation on
[creating branches](https://help.github.com/articles/creating-and-deleting-branches-within-your-repository/)
and
[using pull requests](https://help.github.com/articles/using-pull-requests/).

### How we handle proposals

We use GitHub to track proposed changes via its
[issue tracker](https://github.com/l3montree-dev/flawfix/issues) and
[pull requests](https://github.com/l3montree-dev/flawfix/pulls).
Specific changes are proposed using those mechanisms.
Issues are assigned to an individual, who works it and then marks it complete.
If there are questions or objections, the conversation area of that
issue or pull request is used to resolve it.

### Two-person review

Our policy is that at least 50% of all proposed modifications will be reviewed
before release by a person other than the author,
to determine if it is a worthwhile modification and free of known issues
which would argue against its inclusion.

We achieve this by splitting proposals into two kinds:

1. Low-risk modifications.  These modifications are being proposed by
   people authorized to commit directly, pass all tests, and are unlikely
   to have problems.  These include documentation/text updates and/or updates
   to depedencies already in use where no risk (such as a security risk)
   have been identified.  The project lead can decide that any particular
   modification is low-risk.
2. Other modifications.  These other modifications need to be
   reviewed by someone else or the project lead can decide to accept
   the modification.  Typically this is done by creating a branch and a
   pull request so that it can be reviewed before accepting it.

### Developer Certificate of Origin (DCO)

All contributions (including pull requests) must agree to
the [Developer Certificate of Origin (DCO) version 1.1](./docs/dco.txt).
This is exactly the same one created and used by the Linux kernel developers
and posted on <http://developercertificate.org/>.
This is a developer's certification that he or she has the right to
submit the patch for inclusion into the project.

Simply submitting a contribution implies this agreement, however,
please include a "Signed-off-by" tag in every patch
(this tag is a conventional way to confirm that you agree to the DCO).
You can do this with `git commit --signoff` (the `-s` flag
is a synonym for `--signoff`).

Another way to do this is to write the following at the end of the commit
message, on a line by itself separated by a blank line from the body of
the commit:

````text
Signed-off-by: YOUR NAME <YOUR.EMAIL@EXAMPLE.COM>
````

You can signoff by default in this project by creating a file
(say "git-template") that contains
some blank lines and the signed-off-by text above;
then configure git to use that as a commit template.  For example:

````sh
git config commit.template ~/.git-template
````

It's not practical to fix old contributions in git, so if one is forgotten,
do not try to fix them.  We presume that if someone sometimes used a DCO,
a commit without a DCO is an accident and the DCO still applies.

### License (AGPL-3.0)

All (new) contributed source code must be released
under the [AGPL-3.0](./LICENSE.txt).

### We are proactive

In general we try to be proactive to detect and eliminate
mistakes and vulnerabilities as soon as possible,
and to reduce their impact when they do happen.
We use a defensive design and coding style to reduce the likelihood of mistakes,
a variety of tools that try to detect mistakes early,
and an automatic test suite with significant coverage.
We also release the software as open source software so others can review it.

Since early detection and impact reduction can never be perfect, we also try to
detect and repair problems during deployment as quickly as possible.
This is *especially* true for security issues; see our
[security information](./SECURITY.md) for more.

## Vulnerability reporting (security issues)

Please privately report vulnerabilities you find, so we can fix them!

See [SECURITY.md](./SECURITY.md) for information on how to privately report vulnerabilities.

## Documentation changes

Most of the documentation is in "markdown" format.
All markdown files use the .md filename extension.

Where reasonable, limit yourself to Markdown
that will be accepted by different markdown processors
(e.g., what is specified by CommonMark or the original Markdown)
In practice we use
the version of Markdown implemented by GitHub when it renders .md files,
and you can use its extensions
(in particular, mark code snippets with the programming language used).
This version of markdown is sometimes called
[GitHub-flavored markdown](https://help.github.com/articles/github-flavored-markdown/).
In particular, blank lines separate paragraphs; newlines inside a paragraph
do *not* force a line break.
Beware - this is *not*
the same markdown algorithm used by GitHub when it renders
issue or pull comments; in those cases
[newlines in paragraph-like content are considered as real line breaks](https://help.github.com/articles/writing-on-github/);
unfortunately this other algorithm is *also* called
GitHub rendered markdown.
(Yes, it'd be better if there were standard different names
for different things.)

The style is basically that enforced by the "markdownlint" tool.
Don't use tab characters, avoid "bare" URLs (in a hypertext link, the
link text and URL should be on the same line), and try to limit
lines to 80 characters (but ignore the 80-character limit if that would
create bare URLs).
Using the "rake markdownlint" or "rake" command
(described below) implemented in the development
environment can detect some problems in the markdown.
That said, if you don't know how to install the development environment,
don't worry - we'd rather have your proposals, even if you don't know how to
check them that way.

Do not use trailing two spaces for line breaks, since these cannot be
seen and may be silently removed by some tools.
Instead, use `<br />` (an HTML break).

## Code changes

The code should strive to be DRY (don't repeat yourself),
clear, and obviously correct.
Some technical debt is inevitable, just don't bankrupt us with it.
Improved refactorizations are welcome.

### Automated tests

When adding or changing functionality, please include new tests for them as
part of your contribution.

We encourage tests to be created first, run to ensure they fail, and
then add code to implement the test (aka test driven development).

### Security, privacy, and performance

Pay attention to security, and work *with* (not against) our
security hardening mechanisms.
Protect private information, in particular passwords and email addresses.
Avoid mechanisms that could be used for tracking where possible
(we do need to verify people are logged in for some operations),
and ensure that third parties can't use interactions for tracking.

For more about security, see [security](./SECURITY.md).

We want the software to have decent performance for typical users.
Don't send megabytes of data for a request
(see
[The Website Obesity Crisis](http://idlewords.com/talks/website_obesity.htm)).
Use caching (at the server, and user side) to improve performance
in typical cases (while avoiding making the code too complicated).

There's always a trade-off between various attributes, in particular,
don't make performance so fast that the software is hard to maintain.
Instead, work to get "reasonable" performance in typical cases.

## Reuse (supply chain)

### Requirements for reused components

We prefer reusing components instead of writing lots of code,
but please evaluate all new components before adding them
(including whether or not you need them).
We want to reduce our risks of depending on software that is poorly
maintained or has vulnerabilities (intentional or unintentional).

Prefer software that appears to be currently maintained (e.g., has recent
updates), has more than one developer, and appears to be applying good
practices.

#### License requirements for reused components

All *required* reused software *must* be open source software (OSS).
We use 'license_finder' to help ensure that we're using OSS legally.

In general we want to use GPL-compatible OSS licenses.

For more on license decisions see [docs/dependency_decisions.yml](./docs/dependency_decisions.yml).

Once you've checked, you can approve a library and its license with the
this command (this quickly modifies docs/dependency_decisions.yml;
you can edit the file as well):

````sh
license_finder approval add --who=WHO --why=WHY DEPENDENCY --decisions_file ./docs/dependency_decisions.yml
````

### Updating reused components

Please update only one or few components in each commit, instead of
"everything at once".  This makes debugging problems much easier.

## Aknowledgements

This document is based on the [CONTRIBUTING.md](https://github.com/coreinfrastructure/best-practices-badge/blob/main/CONTRIBUTING.md) of the [OpenSSF Best Practices Badge Programm -  BadgeApp](https://www.bestpractices.dev/en) (CC BY 3.0).

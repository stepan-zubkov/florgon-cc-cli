# Florgon-CC-cli

![](https://img.shields.io/badge/status-Beta-yellow)
![](https://img.shields.io/pypi/dm/florgon-cc-cli)
![](https://img.shields.io/pypi/v/florgon-cc-cli)
![](https://img.shields.io/pypi/status/florgon-cc-cli)
![](https://img.shields.io/pypi/l/florgon-cc-cli)
![](https://img.shields.io/pypi/pyversions/florgon-cc-cli)

Command line interface for https://cc.florgon.com/ service. **Florgon CC** is a powerful url shortener and paste manager. With Florgon CC you can browse your url or paste statistics in web interface or using this CLI. Also Florgon CC generates qr codes for urls. Its functionality is improved with **Florgon SSO**.

## Installation

Florgon-cc-cli built with [click](https://github.com/pallets/click) framework and it is available for Linux, Windows and MacOS X.

Now project is at the Pre-Alpha stage and you can download it directly from [Test PyPI](https://test.pypi.org/):

```bash
pip install --index-url https://test.pypi.org/simple/ florgon-cc-cli
```
Or you can build newer version from sources. Remember this version may contains many bugs.

```bash
pip install git+https://github.com/stepanzubkov/florgon-cc-cli.git#egg=florgon-cc-cli
```

## Usage

Once you have installed the library, you can get help like this:

```bash
florgon-cc --help
```

Create your first short url:

```bash
florgon-cc url create stepanzubkov.github.io
```
Output will be like this:
```
Short url: https://cc.florgon.com/o/x1xx23
Redirects to: https://stepanzubkov.github.io
Expires at: 2023-04-07 12:51:39.813468
```
Pass *-o* flag to get only short url:

```bash
florgon-cc url create https://nometa.xyz/ -o
```

## Contribution

If you find a bug, submit **Issue** here. We are welcome new contributors and testers. Also submit issues and **Pull Requests** to offer new features.

[![GitHub issues by-label](https://img.shields.io/github/issues/stepanzubkov/florgon-cc-cli/good%20first%20issue)](https://github.com/stepanzubkov/florgon-cc-cli/issues?q=is%3Aopen+label%3A%22good+first+issue%22+sort%3Aupdated-desc)
[![GitHub issues by-label](https://img.shields.io/github/issues/stepanzubkov/florgon-cc-cli/help%20wanted)](https://github.com/stepanzubkov/florgon-cc-cli/issues?q=is%3Aopen+label%3A%22help+wanted%22+sort%3Aupdated-desc+)


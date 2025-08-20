<p align="center">
  <img src="https://github.com/user-attachments/assets/9eef5b75-5101-4602-9434-334a37b898e5" width=33% height=33% > 
</p>

# *Threat Exposure Analysis Tool* (TEA-Tool)

**An automated tool that identifies and continuously monitors an organization’s external digital exposure, 
helping strengthen cybersecurity efforts and reduce the risk of cyberattacks by providing insights to stakeholders.**



## Table of Contents
- [Introduction](#Introduction)
- [Features](#Features)
- [Requirements](#Requirements)
- [Installation](#Installation)
- [Usage](#Usage)
- [Configuration](#Configuration)
- [License](#License)

---
## Introduction
The *Threat Exposure Analysis Tool* (TEA-Tool) was developed as part of a bachelor thesis project 
to explore the *Intelligence Gathering* phase of a cyberattack or security assessment with a defensive perspective.

In cybersecurity, an organization's digital footprint is often the first target during reconnaissance by *Threat Actors* (TAs).
This tool aims to provide a continuous or on-demand overview of this external exposure by:

- Identifying publicly accessible IPs, ports, and services
- Highlighting potential vulnerabilities and relevant metadata
- Leveraging *Tactics, Techniques & Procedures* (TTPs) from established security assessment methodologies
- Giving a comprehensive overview of the resulting exposure
- CLI-based interface for quick access and automation

This tool empowers IT security teams with actionable insights to enhance their threat intelligence and overall security posture.

>*"You can't protect what you don't know about."*

**_But Also:_**

TEA-Tool does also work very well for offensive purposes:
  - You only need to supply a _domain name_ to retrieve an overview and possible vulnerabilities for the target's _entire related infrastructure_.
  - The tool is based on passive OSINT from an _Intelligence Gathering_ phase of a security assessment/pen-test/cyberattack
    - So, this tool could possibly automate a part of your security assessment/pen-test ;) 

## Features
- **Discovery Scan**: Uses SHODAN and HackerTarget to identify hostnames, IPs, and ASNs.
- **Full Scan**: Builds on Discovery Scan with the retrieval of port, service, vulnerability and other metadata.
- **Exposure Viewer**: Summarizes or details the exposure found.
- **Scheduled Scans**: Run scans automatically using a saved configuration file.
- **CSV Export**: Export exposure results to a CSV file for further analysis.

---

## Requirements
- Python 3.12 or higher (have been verified, but older versions may still work)

- This guide assumes a Linux environment (Debian-based)

- TEA-Tool works for **free**, without any API keys, but:
  - (optional) A paid SHODAN API Key is recommended for fully detailed results
      - [Get your API key here](https://account.shodan.io/) (the free API key does not have sufficient access)

- (optional) A `.env` file within the root directory of the TEA-Tool repository.
  - Not directly required, but this file applies the API key persistently for the tool.
  - This file is used to store your SHODAN API key and other configuration settings, see [Configuration](#Configuration) for more details.



## Installation
The TEA-Tool currently support two different ways of installation.
- [Standard Install](#standard-install), is the default installation method.
- [Docker Install](#docker-install) (easiest method), is an alternative method allowing for the containeration of the TEA-Tool.

For both installation methods, clone the repository as normal:
```sh
git clone https://github.com/Fleischrr/TEA-Tool.git
```

#### Standard Install
It is recommended to use a Virtualenv to avoid dependency conflicts with other Python projects.
For installation methods not using Virtualenv, you already know what you're doing.

Verify or install Python Virtualenv with (note Python `3.12` is used in this example):
```sh
sudo apt install python3.12-venv
```

Create and activate Virtualenv:
```sh
python3 -m venv .teaenv
```
```sh
source .teaenv/bin/activate
```

Install `requirements.txt` when Virtualenv is active:
```sh
pip3 install -r requirements.txt
```


### Docker Install
Here is an example to use docker container as an installation method.
After cloning the repository, within the cloned repo, run these docker commands to build the TEA-Tool.

Build and run the TEA-Tool:
```sh
docker compose build

docker compose up -d
```


## Usage
The TEA-Tool is designed to be run from the *Command Line Interface* (CLI).
It can be used in two ways: **Main Usage** and **Headless Usage**, 
where the **Main Usage** is the default and recommended method for most users:

- [Main Usage](#Main-Usage)
- [Headless Usage](#Headless-Usage)


### Main Usage

This will display the TEA-Tool's main menu *User Interface* (UI) with instructions.
More explanation of the tool's UI usage is available within the main menu,
or in the documentation under the docs folder.

Launch the tool with:
```sh
python tea_tool.py
```
Or if installed with Docker, run this command to enter into the TEA-Tool main menu within the container (`CTRL+d` to exit container):
```sh
docker compose exec tea-tool bash
```
>NOTE: One can potentially make an alias or wrapper for this command to simplify tool startup if wanted. (i.e. `alias tea-tool="docker compose exec tea-tool bash"`)


After starting the tooll, it will display one of three main menus, depending on terminal size, where you can choose between the TEA-Tool's features:

<p align="center">
  <img src="https://github.com/user-attachments/assets/056015c9-46ab-4933-b232-fc9239ff6a78" width=100% height=100% > 
</p>


### Headless Usage

To use exportation and automation/headless operations, use the tool's available headless CLI arguments.
These arguments do not require the main menu UI to be displayed, which allows for automation and scheduled scans.

These arguments can be viewed with the `-h` or `--help` flag:
```sh
python tea_tool.py -h
```
```
usage: tea_tool.py [-h] [-s ../path/to/config.json | -x ../path/to/output.csv]

The TEA-Tool.
An open-source Threat Exposure Analysis CLI Tool.

options:
  -h, --help            show this help message and exit

Optional arguments:
  Headless options to schedule scans or export data.

  -s, --schedule ../path/to/config.json
                        Schedule configuration file path
  -x, --export ../path/to/output.csv
                        Path to exported TEA exposure data (CSV format)
```

## Configuration
The configuration file is read from the root directory with the file name `.env`.
This file is not included in the repository for security reasons.

The file is structured as follows:
```
SHODAN_API_KEY=your_api_key    # Optional
EXPOSURE_DB_PATH=/custom/path/to/db.sqlite    # Optional
LOG_PATH=/custom/path/to/    # Optional
```

**Explanation**
- `SHODAN_API_KEY`: Your SHODAN API key. This is optional but recommended to get all of the tool's details. ([Get your API key here](https://account.shodan.io/))
- `EXPOSURE_DB_PATH`: Optional path for the SQLite database file. If not specified, the default path is used.
- `LOG_PATH`: Optional path for the log file. If not specified, the default path is used.

> A paid SHODAN account is *recommended* for full detail, but is **not required** for the tool to function.


## License
This project is licensed under the MIT License. See the LICENSE file for details.

---

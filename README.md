# The FortiAppSec Cloud Hands-on Lab

## Prerequisites

Before you can generate the documentation, you need to install the following packages:

```bash
pip install mkdocs mkdocs-material mkdocs-glightbox mkdocs-with-pdf
```

## Clone the Repository

To clone the project repository and navigate to its root directory, execute the following commands:

```bash
git clone https://github.com/benoitbMTL/fortiappsec-hol.git
cd fortiappsec-hol
```

See the instructions below on how to create SSH keys.

## Serving Documentation Locally

To view the documentation locally on your machine, use the following command:

```bash
mkdocs serve
```

Open your browser and navigate to <http://localhost:8000>.

## Building Static HTML Documentation

To generate the HTML version of the documentation, execute:

```bash
mkdocs build
```

This will generate a new directory called `site`. Browse the contents of this directory to find the source documentation converted into HTML files.

## Running the Hands-On-Lab in Docker

To run the Hands-on-Lab in a Docker container, execute the following commands:

```bash
git clone https://github.com/benoitbMTL/fortiappsec-hol.git
cd fortiappsec-hol
chmod +x deploy.sh
bash deploy.sh
```
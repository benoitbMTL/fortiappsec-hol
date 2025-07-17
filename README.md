# The Fortinet Secure Cloud Blueprint Hands-on Lab

## Prerequisites

Before you can generate the documentation, you need to install the following packages:

```bash
pip install mkdocs mkdocs-material mkdocs-glightbox
```

## Clone the Repository

To clone the project repository and navigate to its root directory, execute the following commands:

```bash
git clone git@github.com:benoitbMTL/fortinet-secure-cloud-blueprint-hol.git
cd fortinet-secure-cloud-blueprint-hol
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
git clone git@github.com:benoitbMTL/fortinet-secure-cloud-blueprint-hol.git
cd fortinet-secure-cloud-blueprint-hol
chmod +x deploy.sh
bash deploy.sh
```

## Setting up SSH keys

Step-by-step instructions for setting up SSH keys to access and manage repositories on GitHub.com securely.

- To securely interact with GitHub repositories, it's recommended to authenticate using SSH keys.
- You'll need to generate a new SSH key on your local machine for authentication.

```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
```

- After generating your SSH key, add the public key to your GitHub account for secure access.
- For more detailed information, visit the [official GitHub documentation](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent).

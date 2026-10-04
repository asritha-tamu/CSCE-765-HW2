# CSCE-765-HW2
This README documents the setup used for this homework.

---

## Lab preperation

The homework was performed inside an Ubuntu 24.04 LTS x86-64 virtual machine using VirtualBox.

install python3.12-venv package using below command
- sudo apt install python3.12-venv

To create virtual environment run the command
- python2 -m venv .venv

Activate the environment using
- source .venv/bin/activate

In this homework, we need other packages like cryptography and pytest. Install them using
- python -m pip install cryptography==49.0.0 pytest==9.1.1

Verify the installation using below command. It should show you versions of packages
- python -m pip show cryptography pytest

## Run Python files

You can run the python files using the command 
- python3 <filename.py>

## Run test files

You can run the test files using the command 
- pytest -v <filename.py>

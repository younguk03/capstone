#!/bin/bash

git lfs install
git lfs pull
cd /opt/render/project/src
git pull


pip install -r requirements.txt

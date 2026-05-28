#!/bin/sh
# Ensures the script exits immediately if any command fails.
# The following function is adapted from https://github.com/jansvensen/panw-airs-lab-modelsecurity/blob/main/setup-lab.sh
# Copyright (c) 2024 jansvensen (MIT License)

set -e

# Create and activate virtual environment
python3.12 -m venv venv # v 3.12 required by the model scan client af of 2025-10-30
source venv/bin/activate

# Set environment variables based on the .env file
export $(grep -v '^#' .env | xargs)

# Run the PAN script to generate the pip index link (https://docs.paloaltonetworks.com/ai-runtime-security/ai-model-security/model-security-to-secure-your-ai-models/get-started-with-ai-model-security/install-ai-model-security):**
# Push the output to a variable.
pipindexlink=$(./getPYPIurl.sh)

# Install the model-security-client
pip install model-security-client --extra-index-url $pipindexlink

# Install dependencies:**
pip install -r requirements.txt

# Update pip
pip install --upgrade pip
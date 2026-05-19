#!/bin/bash
echo "Installing dependencies for NIDS Vanguard..."
pip install -r requirements.txt

echo "Starting Streamlit App..."
streamlit run app.py

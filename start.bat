@echo off
echo Installing dependencies for NIDS Vanguard...
python -m pip install -r requirements.txt

echo Starting Streamlit App...
python -m streamlit run app.py
pause

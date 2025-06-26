#!/bin/bash
echo "[+] Running Nmap Scanner Test"
python -m core.nmap_scanner
echo "[+] Testing Metasploit Connection"
python -m core.metasploit_client
echo "[+] Testing AI Recommendations"
python -m ai_engine.recommendation_system

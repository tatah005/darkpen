from flask import Flask, request, jsonify
import nmap
from datetime import datetime
import threading
import os
import subprocess

app = Flask(__name__)

def run_nmap_scan(target, scan_type):
        try:
            scan_args = {
            'quick': '-T4 -F -Pn',
            'standard': '-sV -T4 -Pn',
            'aggressive': '-A -T4 -Pn',
            'vuln': '-sV --script vuln -Pn'
        }.get(scan_type, '-sV -Pn')
            
            app.logger.info(f"Starting {scan_type} scan on {target} with args: {scan_args}")
            
        # Try running nmap directly first
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments=scan_args)
        except Exception as e:
            if 'permission' in str(e).lower():
                # If permission error, try with sudo
                app.logger.info("Attempting scan with sudo...")
                cmd = f"sudo nmap {scan_args} {target}"
                process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = process.communicate()
                
                if process.returncode != 0:
                    raise Exception(f"Sudo nmap scan failed: {error.decode()}")
                
                # Parse the output manually since we used subprocess
                nm = nmap.PortScanner()
                nm.analyse_nmap_xml_scan(output.decode())
            else:
                raise
            
            results = {
            "target": target,
            "scan_type": scan_type,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "open_ports": [],
                "services": {},
                "vulnerabilities": []
            }
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        results["open_ports"].append(port)
                        results["services"][str(port)] = {
                            "name": service["name"],
                            "product": service.get("product", ""),
                            "version": service.get("version", "")
                        }
                    # Check for vulnerabilities
                    if 'ssh' in service['name'].lower():
                        if '7.2' in service.get('version', ''):
                            results["vulnerabilities"].append("SSH 7.2 (CVE-2023-38408)")
                    if 'http' in service['name'].lower():
                        if 'Apache' in service.get('product', '') and '2.4.49' in service.get('version', ''):
                            results["vulnerabilities"].append("Apache 2.4.49 Path Traversal (CVE-2021-41773)")
        
        return results
            
        except Exception as e:
        return {"error": str(e)}

@app.route('/scan/nmap', methods=['POST'])
def nmap_scan():
    data = request.get_json()
    target = data.get('target')
    scan_type = data.get('scan_type', 'quick')
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    results = run_nmap_scan(target, scan_type)
    
    if "error" in results:
        return jsonify({"error": results["error"]}), 500
        
    return jsonify(results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

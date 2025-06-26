from pymetasploit3.msfrpc import MsfRpcClient
import subprocess
import time
import os
from typing import Dict, List, Optional

class MetasploitHandler:
    def __init__(self):
        self.client = None
        self.console_id = None
        self.msfrpcd_process = None

    def start_msfrpcd(self, password: str = 'abc123') -> bool:
        """Start the Metasploit RPC daemon"""
        try:
            # Check if msfrpcd is already running
            if self.msfrpcd_process and self.msfrpcd_process.poll() is None:
                return True

            # Start msfrpcd
            cmd = f"msfrpcd -P {password} -S -a 127.0.0.1"
            self.msfrpcd_process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for the service to start
            time.sleep(5)
            
            # Try to connect
            try:
                self.client = MsfRpcClient(password)
                return True
            except:
                return False

        except Exception as e:
            print(f"Error starting msfrpcd: {str(e)}")
            return False

    def stop_msfrpcd(self):
        """Stop the Metasploit RPC daemon"""
        if self.msfrpcd_process:
            self.msfrpcd_process.terminate()
            self.msfrpcd_process.wait()
            self.msfrpcd_process = None
        if self.client:
            self.client = None

    def create_console(self) -> bool:
        """Create a new Metasploit console"""
        try:
            if not self.client:
                return False
            
            console = self.client.consoles.console()
            self.console_id = console.cid
            return True
        except:
            return False

    def destroy_console(self):
        """Destroy the current console"""
        if self.client and self.console_id:
            self.client.consoles.destroy(self.console_id)
            self.console_id = None

    def execute_module(self, module_type: str, module_name: str, options: Dict) -> Dict:
        """Execute a Metasploit module"""
        try:
            if not self.client:
                return {"success": False, "message": "Not connected to Metasploit"}

            # Get the module
            module = getattr(self.client.modules, module_type)
            
            # Execute the module
            job_id = module.execute(module_name, options)
            
            return {
                "success": True,
                "job_id": job_id,
                "message": f"Module {module_name} executed successfully"
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Error executing module: {str(e)}"
            }

    def check_module(self, module_type: str, module_name: str, options: Dict) -> Dict:
        """Check if target is vulnerable to a specific module"""
        try:
            if not self.client:
                return {"success": False, "message": "Not connected to Metasploit"}

            # Get the module
            module = getattr(self.client.modules, module_type)
            
            # Run the check
            result = module.check(module_name, options)
            
            return {
                "success": True,
                "vulnerable": result,
                "message": "Check completed successfully"
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Error checking module: {str(e)}"
            }

    def get_module_options(self, module_type: str, module_name: str) -> Dict:
        """Get options for a specific module"""
        try:
            if not self.client:
                return {"success": False, "message": "Not connected to Metasploit"}

            # Get the module
            module = getattr(self.client.modules, module_type)
            
            # Get options
            options = module.options(module_name)
            
            return {
                "success": True,
                "options": options
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Error getting module options: {str(e)}"
            }

    def get_job_status(self, job_id: str) -> Dict:
        """Get the status of a running job"""
        try:
            if not self.client:
                return {"success": False, "message": "Not connected to Metasploit"}

            # Check if job is still running
            jobs = self.client.jobs.list
            if job_id in jobs:
                return {
                    "success": True,
                    "status": "running",
                    "info": jobs[job_id]
                }
            else:
                return {
                    "success": True,
                    "status": "completed"
                }
        except Exception as e:
            return {
                "success": False,
                "message": f"Error checking job status: {str(e)}"
            }

    def stop_job(self, job_id: str) -> Dict:
        """Stop a running job"""
        try:
            if not self.client:
                return {"success": False, "message": "Not connected to Metasploit"}

            # Stop the job
            self.client.jobs.stop(job_id)
            
            return {
                "success": True,
                "message": f"Job {job_id} stopped successfully"
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Error stopping job: {str(e)}"
            }

    def get_module_list(self, module_type: str) -> List[str]:
        """Get list of available modules for a specific type"""
        try:
            if not self.client:
                return []

            # Get the module list
            module = getattr(self.client.modules, module_type)
            return module.list
        except:
            return [] 
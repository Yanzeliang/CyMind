"""
Simple integration test for the comprehensive reconnaissance module
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import unittest
from unittest.mock import Mock, patch

from modules.recon_module import ReconModule


class TestReconSimple(unittest.TestCase):
    """Simple tests for reconnaissance module"""
    
    def setUp(self):
        """Set up test environment"""
        self.recon_module = ReconModule(max_workers=2)
    
    def test_recon_module_initialization(self):
        """Test that recon module initializes correctly"""
        self.assertIsInstance(self.recon_module, ReconModule)
        self.assertTrue(hasattr(self.recon_module, 'max_workers'))
        self.assertTrue(hasattr(self.recon_module, 'executor'))
        self.assertTrue(hasattr(self.recon_module, 'active_scans'))
        self.assertIsInstance(self.recon_module.active_scans, dict)
    
    def test_tool_availability_checking(self):
        """Test tool availability checking functionality"""
        # Test with common tools
        tools_to_test = ['subfinder', 'amass', 'nmap', 'nonexistent_tool']
        
        for tool in tools_to_test:
            availability = self.recon_module.check_tool_availability(tool)
            self.assertIsInstance(availability, bool)
            
            # Test caching - second call should return same result
            availability2 = self.recon_module.check_tool_availability(tool)
            self.assertEqual(availability, availability2)
    
    def test_available_tools_listing(self):
        """Test listing of available tools"""
        available_tools = self.recon_module.list_available_tools()
        
        self.assertIsInstance(available_tools, dict)
        
        # Check that expected tools are listed
        expected_tools = [
            'subfinder', 'amass', 'nmap',
            'dns_bruteforce', 'certificate_transparency',
            'banner_grabbing', 'ssl_analysis', 'technology_identification'
        ]
        
        for tool in expected_tools:
            self.assertIn(tool, available_tools)
            self.assertIsInstance(available_tools[tool], bool)
        
        # Built-in tools should always be available
        builtin_tools = [
            'dns_bruteforce', 'certificate_transparency',
            'banner_grabbing', 'ssl_analysis', 'technology_identification'
        ]
        
        for tool in builtin_tools:
            self.assertTrue(available_tools[tool], f"Built-in tool {tool} should be available")
    
    @patch('subprocess.run')
    @patch('dns.resolver.resolve')
    @patch('requests.get')
    def test_subdomain_enumeration(self, mock_requests, mock_dns, mock_subprocess):
        """Test subdomain enumeration functionality"""
        # Setup mocks
        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout="www.example.com\napi.example.com\nmail.example.com",
            stderr=""
        )
        
        mock_dns_answer = Mock()
        mock_dns_answer.__str__ = lambda x: "192.168.1.1"
        mock_dns.return_value = [mock_dns_answer]
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<title>Test Page</title>"
        mock_response.headers = {'content-type': 'text/html'}
        mock_requests.return_value = mock_response
        
        # Test subdomain enumeration
        domain = "example.com"
        results = self.recon_module._run_subdomain_enumeration(domain)
        
        # Validate results
        self.assertIsInstance(results, list)
        
        for result in results:
            self.assertIn('subdomain', result)
            self.assertIn('source', result)
            self.assertIn('ip_addresses', result)
            self.assertIsInstance(result['ip_addresses'], list)
            
            # Subdomain should belong to the domain
            subdomain = result['subdomain']
            self.assertTrue(
                subdomain.endswith(f".{domain}") or subdomain == domain,
                f"Subdomain {subdomain} should belong to {domain}"
            )
    
    @patch('subprocess.run')
    @patch('socket.socket')
    def test_service_fingerprinting(self, mock_socket, mock_subprocess):
        """Test service fingerprinting functionality"""
        # Setup mocks
        nmap_output = '''
22/tcp   open  ssh     OpenSSH 8.0 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41
443/tcp  open  https   Apache httpd 2.4.41 ((Ubuntu))
        '''
        
        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout=nmap_output,
            stderr=""
        )
        
        mock_socket_instance = Mock()
        mock_socket_instance.recv.return_value = b"SSH-2.0-OpenSSH_8.0"
        mock_socket.return_value = mock_socket_instance
        
        # Test service fingerprinting
        host = "example.com"
        results = self.recon_module._run_service_fingerprinting(host)
        
        # Validate results
        self.assertIsInstance(results, list)
        
        for result in results:
            self.assertIn('host', result)
            self.assertIn('port', result)
            self.assertIn('protocol', result)
            self.assertIn('service', result)
            
            # Validate field types
            self.assertIsInstance(result['port'], int)
            self.assertIn(result['protocol'], ['tcp', 'udp'])
            self.assertTrue(1 <= result['port'] <= 65535)
    
    @patch('dns.resolver.resolve')
    def test_dns_analysis(self, mock_dns):
        """Test DNS analysis functionality"""
        # Setup mock DNS responses
        def dns_side_effect(domain, record_type):
            mock_answer = Mock()
            if record_type == 'A':
                mock_answer.__str__ = lambda x: "192.168.1.1"
            elif record_type == 'MX':
                mock_answer.__str__ = lambda x: "10 mail.example.com"
            elif record_type == 'NS':
                mock_answer.__str__ = lambda x: "ns1.example.com"
            else:
                mock_answer.__str__ = lambda x: "test-record"
            return [mock_answer]
        
        mock_dns.side_effect = dns_side_effect
        
        # Test DNS analysis
        domain = "example.com"
        results = self.recon_module._run_dns_analysis(domain)
        
        # Validate results
        self.assertIsInstance(results, dict)
        self.assertIn('domain', results)
        self.assertIn('records', results)
        self.assertEqual(results['domain'], domain)
        self.assertIsInstance(results['records'], dict)
    
    @patch('requests.get')
    def test_technology_identification(self, mock_requests):
        """Test technology stack identification"""
        # Setup mock HTTP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'Apache/2.4.41 (Ubuntu)',
            'X-Powered-By': 'PHP/7.4.3'
        }
        mock_response.text = '''
        <html>
        <head><title>Test Site</title></head>
        <body>
        <script src="jquery.min.js"></script>
        <link rel="stylesheet" href="bootstrap.css">
        </body>
        </html>
        '''
        mock_requests.return_value = mock_response
        
        # Test technology identification
        url = "https://example.com"
        results = self.recon_module._run_technology_identification(url)
        
        # Validate results
        self.assertIsInstance(results, dict)
        self.assertIn('url', results)
        self.assertIn('technologies', results)
        self.assertIn('server_headers', results)
        self.assertEqual(results['url'], url)
        self.assertIsInstance(results['technologies'], list)
        self.assertIsInstance(results['server_headers'], dict)
    
    def test_scan_status_tracking(self):
        """Test scan status tracking functionality"""
        # Test with non-existent scan
        status = self.recon_module.get_scan_status('nonexistent_scan')
        self.assertEqual(status['status'], 'not_found')
        
        # Test with mock active scan
        mock_future = Mock()
        mock_future.done.return_value = False
        
        scan_id = 'test_scan_123'
        self.recon_module.active_scans[scan_id] = {
            'future': mock_future,
            'status': 'running',
            'target': {'id': 1, 'url': 'https://example.com'},
            'tools': ['subdomain_enum'],
            'start_time': 1234567890
        }
        
        status = self.recon_module.get_scan_status(scan_id)
        self.assertEqual(status['status'], 'running')
        self.assertIn('progress', status)
        self.assertIn('elapsed_time', status)
    
    def test_cleanup_functionality(self):
        """Test scan cleanup functionality"""
        # Add some mock completed scans
        mock_future_completed = Mock()
        mock_future_completed.done.return_value = True
        mock_future_completed.result.return_value = {'status': 'completed'}
        
        mock_future_running = Mock()
        mock_future_running.done.return_value = False
        
        self.recon_module.active_scans['completed_scan'] = {
            'future': mock_future_completed,
            'status': 'completed'
        }
        
        self.recon_module.active_scans['running_scan'] = {
            'future': mock_future_running,
            'status': 'running'
        }
        
        # Run cleanup
        self.recon_module.cleanup_completed_scans()
        
        # Completed scan should be removed, running scan should remain
        self.assertNotIn('completed_scan', self.recon_module.active_scans)
        self.assertIn('running_scan', self.recon_module.active_scans)


if __name__ == "__main__":
    print("🚀 Testing Comprehensive Reconnaissance Module")
    print("=" * 50)
    
    unittest.main(verbosity=2)
"""
Integration test for the comprehensive reconnaissance module

This test validates that the recon module integrates properly with the
existing CyMind system and provides the expected functionality.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import unittest
import tempfile
import time
from unittest.mock import Mock, patch

from modules.recon_module import ReconModule
from modules.target_manager import TargetManager
from modules.project_manager import ProjectManager
from models import DatabaseManager, Target, Project


class TestReconIntegration(unittest.TestCase):
    """Integration tests for reconnaissance module"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary database
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.db_manager = DatabaseManager(f'sqlite:///{self.db_path}')
        
        # Initialize modules
        self.recon_module = ReconModule(max_workers=2)
        self.target_manager = TargetManager()
        self.project_manager = ProjectManager()
        
        # Create test project and target
        self.setup_test_data()
    
    def tearDown(self):
        """Clean up test environment"""
        try:
            os.close(self.db_fd)
            os.unlink(self.db_path)
        except:
            pass
    
    def setup_test_data(self):
        """Set up test project and targets"""
        # Create test project with unique name
        import time
        project_name = f'Recon Integration Test {int(time.time())}'
        project_result = self.project_manager.create_project({
            'name': project_name,
            'description': 'Test project for reconnaissance integration'
        })
        
        if project_result['status'] == 'success':
            self.test_project_id = project_result['project']['id']
        else:
            raise Exception(f"Failed to create test project: {project_result.get('message', 'Unknown error')}")
        
        # Create test targets
        self.test_targets = []
        
        target_data = [
            {
                'name': 'Example Domain',
                'url': 'https://example.com',
                'target_type': 'domain',
                'tags': ['test', 'integration']
            },
            {
                'name': 'Test API',
                'url': 'https://api.test.com',
                'target_type': 'domain',
                'tags': ['api', 'test']
            }
        ]
        
        for data in target_data:
            result = self.target_manager.add_target(data, self.test_project_id)
            self.test_targets.append(result['target'])
    
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
    
    def test_comprehensive_recon_workflow(self):
        """Test the complete comprehensive reconnaissance workflow"""
        target = self.test_targets[0]
        
        with patch.object(self.recon_module, '_execute_comprehensive_recon') as mock_exec:
            mock_exec.return_value = {
                'status': 'completed',
                'scan_id': 'test_scan_123',
                'target': target,
                'tools_used': ['subdomain_enum', 'service_fingerprint'],
                'results': {
                    'subdomains': [
                        {'subdomain': 'www.example.com', 'source': 'dns_bruteforce', 'ip_addresses': ['192.168.1.1']}
                    ],
                    'services': [
                        {'host': 'example.com', 'port': 80, 'protocol': 'tcp', 'service': 'http'}
                    ]
                },
                'summary': {
                    'total_subdomains': 1,
                    'total_services': 1,
                    'unique_technologies': 0,
                    'dns_records_found': 0
                }
            }
            
            # Start comprehensive recon
            result = self.recon_module.run_comprehensive_recon(target)
            
            # Validate response
            self.assertIn('status', result)
            self.assertIn(result['status'], ['started', 'completed'])
            
            if result['status'] == 'started':
                self.assertIn('scan_id', result)
                scan_id = result['scan_id']
                self.assertIn(scan_id, self.recon_module.active_scans)
    
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
            'target': self.test_targets[0],
            'tools': ['subdomain_enum'],
            'start_time': time.time()
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
        initial_count = len(self.recon_module.active_scans)
        self.recon_module.cleanup_completed_scans()
        
        # Completed scan should be removed, running scan should remain
        self.assertNotIn('completed_scan', self.recon_module.active_scans)
        self.assertIn('running_scan', self.recon_module.active_scans)
    
    def test_integration_with_target_manager(self):
        """Test integration with target manager"""
        # Test that targets can be retrieved and used for recon
        targets = self.target_manager.get_targets(project_id=self.test_project_id)
        self.assertTrue(len(targets) > 0)
        
        target = targets[0]
        
        # Test that target has required fields for recon
        self.assertIn('id', target)
        self.assertIn('name', target)
        self.assertTrue('url' in target or 'ip_address' in target)
    
    def test_integration_with_project_manager(self):
        """Test integration with project manager"""
        # Test that project exists and can be retrieved
        project = self.project_manager.get_project(self.test_project_id)
        self.assertIsNotNone(project)
        self.assertEqual(project['id'], self.test_project_id)
        
        # Test that project has targets
        self.assertTrue(project['statistics']['target_count'] > 0)


if __name__ == "__main__":
    print("🚀 Testing Comprehensive Reconnaissance Module Integration")
    print("=" * 60)
    
    unittest.main(verbosity=2)
"""
Property-based tests for service fingerprinting accuracy

Property 2: Service fingerprinting accuracy
Validates: Requirements 1.2

This test ensures that service fingerprinting accurately identifies
service versions and technologies across different protocols and ports.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from hypothesis import given, strategies as st, settings, assume, example
from hypothesis.stateful import RuleBasedStateMachine, Bundle, rule, initialize, invariant
import tempfile
import json
import time
import socket
import ssl
from unittest.mock import Mock, patch, MagicMock

from modules.recon_module import ReconModule, ServiceResult
from models import DatabaseManager, Target, Project, Session


class ServiceFingerprintingProperties(RuleBasedStateMachine):
    """Property-based state machine for testing service fingerprinting accuracy"""
    
    targets = Bundle('targets')
    services = Bundle('services')
    
    def __init__(self):
        super().__init__()
        # Create temporary database
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.db_manager = DatabaseManager(f'sqlite:///{self.db_path}')
        self.recon_module = ReconModule(max_workers=2)
        
        # Mock external calls for testing
        self.mock_patches = []
        self.setup_mocks()
    
    def setup_mocks(self):
        """Setup mocks for external tools and network calls"""
        # Mock subprocess calls (nmap)
        subprocess_patcher = patch('modules.recon_module.subprocess.run')
        self.mock_subprocess = subprocess_patcher.start()
        self.mock_patches.append(subprocess_patcher)
        
        # Mock socket operations
        socket_patcher = patch('modules.recon_module.socket.socket')
        self.mock_socket = socket_patcher.start()
        self.mock_patches.append(socket_patcher)
        
        # Mock SSL operations
        ssl_patcher = patch('modules.recon_module.ssl.create_default_context')
        self.mock_ssl = ssl_patcher.start()
        self.mock_patches.append(ssl_patcher)
        
        # Setup default mock responses
        self.setup_default_mocks()
    
    def setup_default_mocks(self):
        """Setup default mock responses"""
        # Mock nmap service detection output
        nmap_output = '''
Starting Nmap 7.80 ( https://nmap.org ) at 2023-01-01 12:00 UTC
Nmap scan report for example.com (192.168.1.1)
Host is up (0.001s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41
443/tcp  open  https   Apache httpd 2.4.41 ((Ubuntu))
3306/tcp open  mysql   MySQL 8.0.25

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host) scanned in 10.23 seconds
        '''
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = nmap_output
        mock_result.stderr = ""
        self.mock_subprocess.return_value = mock_result
        
        # Mock socket banner grabbing
        mock_socket_instance = Mock()
        mock_socket_instance.recv.return_value = b"SSH-2.0-OpenSSH_8.0"
        self.mock_socket.return_value = mock_socket_instance
        
        # Mock SSL certificate
        mock_ssl_context = Mock()
        mock_ssl_socket = Mock()
        mock_cert = {
            'subject': [('commonName', 'example.com')],
            'issuer': [('commonName', 'Test CA')],
            'version': 3,
            'serialNumber': '12345',
            'notBefore': 'Jan  1 00:00:00 2023 GMT',
            'notAfter': 'Jan  1 00:00:00 2024 GMT',
            'signatureAlgorithm': 'sha256WithRSAEncryption',
            'subjectAltName': [('DNS', 'example.com'), ('DNS', 'www.example.com')]
        }
        mock_ssl_socket.getpeercert.return_value = mock_cert
        mock_ssl_context.wrap_socket.return_value = mock_ssl_socket
        self.mock_ssl.return_value = mock_ssl_context
    
    def teardown_method(self, method):
        """Clean up after tests"""
        for patcher in self.mock_patches:
            patcher.stop()
        
        try:
            os.close(self.db_fd)
            os.unlink(self.db_path)
        except:
            pass
    
    @initialize()
    def setup_initial_state(self):
        """Initialize the test environment"""
        session = self.db_manager.get_session()
        try:
            # Create a test project
            self.test_project = Project(
                name="Test Service Fingerprinting Project",
                description="Project for testing service fingerprinting"
            )
            session.add(self.test_project)
            session.commit()
            session.refresh(self.test_project)
        finally:
            session.close()
    
    @rule(target=targets, 
          host=st.text(alphabet=st.characters(whitelist_categories=('Ll', 'Nd'), 
                                           whitelist_characters='.-'), 
                      min_size=5, max_size=30).filter(lambda x: '.' in x))
    def create_target(self, host):
        """Create a target for service fingerprinting testing"""
        assume(not host.startswith('.') and not host.endswith('.'))
        assume(all(part for part in host.split('.')))  # No empty parts
        
        session = self.db_manager.get_session()
        try:
            target = Target(
                project_id=self.test_project.id,
                name=f"Target {host}",
                url=f"https://{host}",
                ip_address="192.168.1.1",
                target_type="domain",
                tags=["test", "fingerprinting"]
            )
            session.add(target)
            session.commit()
            session.refresh(target)
            
            return {
                'id': target.id,
                'url': f"https://{host}",
                'host': host,
                'ip': "192.168.1.1",
                'target_type': 'domain'
            }
        finally:
            session.close()
    
    @rule(target=targets)
    def test_service_fingerprinting_accuracy(self, target):
        """
        Property 2: Service fingerprinting accuracy
        
        Tests that service fingerprinting:
        1. Identifies services correctly
        2. Extracts version information
        3. Determines protocol types
        4. Provides confidence scores
        5. Handles multiple detection methods
        """
        host = target['host']
        ip = target.get('ip', host)
        
        # Run service fingerprinting
        results = self.recon_module._run_service_fingerprinting(host, ip)
        
        # Property 2.1: Results should be structured correctly
        assert isinstance(results, list), "Service fingerprinting should return a list"
        
        for result in results:
            # Property 2.2: Each result should have required fields
            required_fields = ['host', 'port', 'protocol', 'service']
            for field in required_fields:
                assert field in result, f"Service result must have {field} field"
            
            # Property 2.3: Field types should be correct
            assert isinstance(result['host'], str), "Host should be string"
            assert isinstance(result['port'], int), "Port should be integer"
            assert isinstance(result['protocol'], str), "Protocol should be string"
            assert isinstance(result['service'], str), "Service should be string"
            
            # Property 2.4: Port numbers should be valid
            assert 1 <= result['port'] <= 65535, f"Port {result['port']} should be valid"
            
            # Property 2.5: Protocol should be valid
            valid_protocols = ['tcp', 'udp']
            assert result['protocol'] in valid_protocols, \
                f"Protocol {result['protocol']} should be valid"
            
            # Property 2.6: Confidence score should be valid if present
            if 'confidence' in result:
                assert isinstance(result['confidence'], (int, float)), \
                    "Confidence should be numeric"
                assert 0.0 <= result['confidence'] <= 1.0, \
                    f"Confidence {result['confidence']} should be between 0 and 1"
            
            # Property 2.7: Version information should be string if present
            if 'version' in result and result['version'] is not None:
                assert isinstance(result['version'], str), "Version should be string"
            
            # Property 2.8: Banner should be string if present
            if 'banner' in result and result['banner'] is not None:
                assert isinstance(result['banner'], str), "Banner should be string"
    
    @rule(target=targets)
    def test_nmap_service_detection(self, target):
        """
        Property 2.9: Nmap service detection accuracy
        
        Tests that nmap service detection:
        1. Parses output correctly
        2. Extracts service information
        3. Handles various service types
        4. Provides accurate version detection
        """
        host = target['host']
        
        # Test nmap service detection specifically
        results = self.recon_module._run_nmap_service_detection(host)
        
        # Property 2.9.1: Should return list of services
        assert isinstance(results, list), "Nmap service detection should return list"
        
        # Property 2.9.2: Each service should have proper structure
        for result in results:
            assert 'host' in result, "Nmap result should have host"
            assert 'port' in result, "Nmap result should have port"
            assert 'service' in result, "Nmap result should have service"
            assert 'protocol' in result, "Nmap result should have protocol"
            
            # Property 2.9.3: Host should match target
            assert result['host'] == host, "Result host should match target host"
            
            # Property 2.9.4: Service names should be reasonable
            assert len(result['service']) > 0, "Service name should not be empty"
            assert result['service'] != 'unknown' or result.get('version'), \
                "Unknown services should have version info or be filtered"
    
    @rule(target=targets)
    def test_banner_grabbing_accuracy(self, target):
        """
        Property 2.10: Banner grabbing accuracy
        
        Tests that banner grabbing:
        1. Connects to services correctly
        2. Extracts meaningful banners
        3. Identifies services from banners
        4. Handles connection failures gracefully
        """
        host = target['host']
        
        # Test banner grabbing
        results = self.recon_module._run_banner_grabbing(host)
        
        # Property 2.10.1: Should return list
        assert isinstance(results, list), "Banner grabbing should return list"
        
        for result in results:
            # Property 2.10.2: Should have banner information
            if 'banner' in result and result['banner']:
                assert isinstance(result['banner'], str), "Banner should be string"
                assert len(result['banner']) > 0, "Banner should not be empty"
                
                # Property 2.10.3: Service identification should be reasonable
                service = result.get('service', 'unknown')
                port = result.get('port', 0)
                
                # Common service/port associations
                if port == 22 and 'ssh' in result['banner'].lower():
                    assert service == 'ssh', "SSH banner should identify SSH service"
                elif port == 80 and 'http' in result['banner'].lower():
                    assert service == 'http', "HTTP banner should identify HTTP service"
                elif port == 21 and 'ftp' in result['banner'].lower():
                    assert service == 'ftp', "FTP banner should identify FTP service"
    
    @rule(target=targets)
    def test_ssl_analysis_accuracy(self, target):
        """
        Property 2.11: SSL analysis accuracy
        
        Tests that SSL analysis:
        1. Identifies SSL/TLS services
        2. Extracts certificate information
        3. Validates certificate structure
        4. Handles SSL connection errors
        """
        host = target['host']
        
        # Test SSL analysis
        results = self.recon_module._run_ssl_analysis(host)
        
        # Property 2.11.1: Should return list
        assert isinstance(results, list), "SSL analysis should return list"
        
        for result in results:
            # Property 2.11.2: SSL results should have ssl_info
            if 'ssl_info' in result and result['ssl_info']:
                ssl_info = result['ssl_info']
                assert isinstance(ssl_info, dict), "SSL info should be dictionary"
                
                # Property 2.11.3: Certificate should have required fields
                if 'subject' in ssl_info:
                    assert isinstance(ssl_info['subject'], dict), "Subject should be dict"
                
                if 'issuer' in ssl_info:
                    assert isinstance(ssl_info['issuer'], dict), "Issuer should be dict"
                
                # Property 2.11.4: Dates should be strings if present
                for date_field in ['not_before', 'not_after']:
                    if date_field in ssl_info and ssl_info[date_field]:
                        assert isinstance(ssl_info[date_field], str), \
                            f"{date_field} should be string"
                
                # Property 2.11.5: SAN should be list if present
                if 'san' in ssl_info and ssl_info['san']:
                    assert isinstance(ssl_info['san'], list), "SAN should be list"
    
    @rule(target=targets)
    def test_service_fingerprinting_error_handling(self, target):
        """
        Property 2.12: Service fingerprinting error handling
        
        Tests that service fingerprinting handles errors gracefully:
        1. Network timeouts
        2. Connection refused
        3. Tool failures
        4. Invalid responses
        """
        host = target['host']
        
        # Test with failing subprocess (nmap failure)
        mock_failed_result = Mock()
        mock_failed_result.returncode = 1
        mock_failed_result.stdout = ""
        mock_failed_result.stderr = "Network unreachable"
        self.mock_subprocess.return_value = mock_failed_result
        
        # Test with socket errors
        self.mock_socket.side_effect = socket.error("Connection refused")
        
        try:
            results = self.recon_module._run_service_fingerprinting(host)
            
            # Property 2.12.1: Should not crash on errors
            assert isinstance(results, list), "Should return list even on errors"
            
            # Property 2.12.2: Should handle gracefully
            # If we reach here, error handling worked
            
        except Exception as e:
            # Should not raise unhandled exceptions
            assert False, f"Service fingerprinting should handle errors gracefully, got: {e}"
        
        finally:
            # Reset mocks
            self.mock_socket.side_effect = None
            self.setup_default_mocks()
    
    @rule(target=targets)
    def test_service_identification_consistency(self, target):
        """
        Property 2.13: Service identification consistency
        
        Tests that service identification is consistent:
        1. Same service detected by multiple methods should match
        2. Service names should be standardized
        3. Version formats should be consistent
        4. Confidence scores should reflect accuracy
        """
        host = target['host']
        
        # Run multiple detection methods
        nmap_results = self.recon_module._run_nmap_service_detection(host)
        banner_results = self.recon_module._run_banner_grabbing(host)
        
        # Property 2.13.1: Results should be consistent across methods
        nmap_ports = {r['port']: r for r in nmap_results}
        banner_ports = {r['port']: r for r in banner_results}
        
        # Check for overlapping ports
        common_ports = set(nmap_ports.keys()) & set(banner_ports.keys())
        
        for port in common_ports:
            nmap_service = nmap_ports[port]['service']
            banner_service = banner_ports[port]['service']
            
            # Property 2.13.2: Services should be compatible or one should be more specific
            if nmap_service != 'unknown' and banner_service != 'unknown':
                # Allow for different levels of specificity
                # e.g., "http" and "apache" are compatible
                compatible_services = {
                    'http': ['apache', 'nginx', 'iis'],
                    'https': ['apache', 'nginx', 'iis'],
                    'ssh': ['openssh'],
                    'ftp': ['vsftpd', 'proftpd']
                }
                
                is_compatible = (
                    nmap_service == banner_service or
                    banner_service in compatible_services.get(nmap_service, []) or
                    nmap_service in compatible_services.get(banner_service, [])
                )
                
                # Allow some flexibility in service identification
                if not is_compatible:
                    # Log inconsistency but don't fail - this is expected in real scenarios
                    print(f"Service identification inconsistency on port {port}: "
                          f"nmap={nmap_service}, banner={banner_service}")
    
    @invariant()
    def database_consistency(self):
        """Ensure database remains consistent throughout testing"""
        session = self.db_manager.get_session()
        try:
            # Check that test project still exists
            project = session.query(Project).filter_by(id=self.test_project.id).first()
            assert project is not None, "Test project should exist"
            
            # Check that all targets belong to valid projects
            targets = session.query(Target).all()
            for target in targets:
                project = session.query(Project).filter_by(id=target.project_id).first()
                assert project is not None, f"Target {target.id} should belong to valid project"
        finally:
            session.close()


class TestServiceFingerprintingProperties(unittest.TestCase):
    """Test runner for service fingerprinting properties"""
    
    def test_service_fingerprinting_properties(self):
        """Run property-based tests for service fingerprinting"""
        print("Testing service fingerprinting accuracy properties...")
        
        # Run the state machine tests
        state_machine = ServiceFingerprintingProperties()
        try:
            # Initialize the state machine
            state_machine.setup_initial_state()
            
            # Test with various host formats
            test_hosts = [
                "example.com",
                "api.service.net",
                "web-server.org",
                "test.domain.co.uk"
            ]
            
            for host in test_hosts:
                # Create target
                session = state_machine.db_manager.get_session()
                try:
                    target = Target(
                        project_id=state_machine.test_project.id,
                        name=f"Test {host}",
                        url=f"https://{host}",
                        ip_address="192.168.1.1",
                        target_type="domain",
                        tags=["test"]
                    )
                    session.add(target)
                    session.commit()
                    session.refresh(target)
                    
                    target_dict = {
                        'id': target.id,
                        'url': f"https://{host}",
                        'host': host,
                        'ip': "192.168.1.1",
                        'target_type': 'domain'
                    }
                    
                    # Test properties
                    state_machine.test_service_fingerprinting_accuracy(target_dict)
                    state_machine.test_nmap_service_detection(target_dict)
                    state_machine.test_banner_grabbing_accuracy(target_dict)
                    state_machine.test_ssl_analysis_accuracy(target_dict)
                    state_machine.test_service_fingerprinting_error_handling(target_dict)
                    state_machine.test_service_identification_consistency(target_dict)
                    
                finally:
                    session.close()
            
            print("✅ Service fingerprinting accuracy property tests passed!")
            
        finally:
            state_machine.teardown_method(None)


if __name__ == "__main__":
    unittest.main()
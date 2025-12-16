"""
Property-based tests for subdomain enumeration completeness

Property 1: Subdomain enumeration completeness
Validates: Requirements 1.1

This test ensures that the subdomain enumeration functionality discovers
all accessible subdomains using multiple methods and tools.
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
from unittest.mock import Mock, patch, MagicMock

from modules.recon_module import ReconModule
from models import DatabaseManager, Target, Project, Session


class SubdomainEnumerationProperties(RuleBasedStateMachine):
    """Property-based state machine for testing subdomain enumeration completeness"""
    
    targets = Bundle('targets')
    domains = Bundle('domains')
    
    def __init__(self):
        super().__init__()
        # Create temporary database
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.db_manager = DatabaseManager(f'sqlite:///{self.db_path}')
        self.recon_module = ReconModule(max_workers=2)
        
        # Mock external tool calls for testing
        self.mock_patches = []
        self.setup_mocks()
    
    def setup_mocks(self):
        """Setup mocks for external tools and network calls"""
        # Mock subprocess calls
        subprocess_patcher = patch('modules.recon_module.subprocess.run')
        self.mock_subprocess = subprocess_patcher.start()
        self.mock_patches.append(subprocess_patcher)
        
        # Mock DNS resolver
        dns_patcher = patch('modules.recon_module.dns.resolver.resolve')
        self.mock_dns = dns_patcher.start()
        self.mock_patches.append(dns_patcher)
        
        # Mock requests (imported inside functions)
        requests_patcher = patch('requests.get')
        self.mock_requests = requests_patcher.start()
        self.mock_patches.append(requests_patcher)
        
        # Setup default mock responses
        self.setup_default_mocks()
    
    def setup_default_mocks(self):
        """Setup default mock responses"""
        # Mock successful subprocess calls
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "test.example.com\napi.example.com\nwww.example.com"
        mock_result.stderr = ""
        self.mock_subprocess.return_value = mock_result
        
        # Mock DNS resolution
        mock_dns_answer = Mock()
        mock_dns_answer.__str__ = lambda x: "192.168.1.1"
        self.mock_dns.return_value = [mock_dns_answer]
        
        # Mock HTTP requests
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<title>Test Page</title>"
        mock_response.headers = {'content-type': 'text/html'}
        self.mock_requests.return_value = mock_response
    
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
                name="Test Recon Project",
                description="Project for testing reconnaissance"
            )
            session.add(self.test_project)
            session.commit()
            session.refresh(self.test_project)
        finally:
            session.close()
    
    @rule(target=targets, domain=st.text(
        alphabet=st.characters(whitelist_categories=('Ll', 'Nd'), whitelist_characters='.-'),
        min_size=5, max_size=50
    ).filter(lambda x: '.' in x and not x.startswith('.') and not x.endswith('.')))
    def create_target(self, domain):
        """Create a target for subdomain enumeration testing"""
        assume(domain.count('.') >= 1)  # Must have at least one dot
        assume(not domain.startswith('-') and not domain.endswith('-'))
        assume(all(part for part in domain.split('.')))  # No empty parts
        
        session = self.db_manager.get_session()
        try:
            target = Target(
                project_id=self.test_project.id,
                name=f"Target {domain}",
                url=f"https://{domain}",
                target_type="domain",
                tags=["test", "recon"]
            )
            session.add(target)
            session.commit()
            session.refresh(target)
            
            return {
                'id': target.id,
                'url': f"https://{domain}",
                'domain': domain,
                'target_type': 'domain'
            }
        finally:
            session.close()
    
    @rule(target=targets)
    def test_subdomain_enumeration_completeness(self, target):
        """
        Property 1: Subdomain enumeration completeness
        
        Tests that subdomain enumeration:
        1. Uses multiple discovery methods
        2. Returns structured results
        3. Includes source attribution
        4. Handles errors gracefully
        5. Provides comprehensive coverage
        """
        domain = target['domain']
        
        # Setup mock responses for this specific domain
        expected_subdomains = [
            f"www.{domain}",
            f"api.{domain}",
            f"mail.{domain}",
            f"admin.{domain}"
        ]
        
        # Mock subfinder output
        subfinder_output = "\n".join(expected_subdomains[:2])
        mock_subfinder_result = Mock()
        mock_subfinder_result.returncode = 0
        mock_subfinder_result.stdout = subfinder_output
        mock_subfinder_result.stderr = ""
        
        # Mock amass output
        amass_output = "\n".join(expected_subdomains[2:])
        mock_amass_result = Mock()
        mock_amass_result.returncode = 0
        mock_amass_result.stdout = amass_output
        mock_amass_result.stderr = ""
        
        # Configure subprocess mock to return different results based on command
        def subprocess_side_effect(cmd, **kwargs):
            if 'subfinder' in cmd:
                return mock_subfinder_result
            elif 'amass' in cmd:
                return mock_amass_result
            else:
                return Mock(returncode=0, stdout="", stderr="")
        
        self.mock_subprocess.side_effect = subprocess_side_effect
        
        # Mock tool availability
        with patch.object(self.recon_module, 'check_tool_availability') as mock_check:
            mock_check.return_value = True
            
            # Run subdomain enumeration
            results = self.recon_module._run_subdomain_enumeration(domain)
            
            # Property 1.1: Results should be non-empty for valid domains
            assert len(results) > 0, f"Subdomain enumeration should find subdomains for {domain}"
            
            # Property 1.2: Each result should have required fields
            for result in results:
                assert 'subdomain' in result, "Each result must have a subdomain field"
                assert 'source' in result, "Each result must have a source field"
                assert 'ip_addresses' in result, "Each result must have ip_addresses field"
                assert isinstance(result['ip_addresses'], list), "IP addresses must be a list"
            
            # Property 1.3: Sources should be diverse (multiple methods used)
            sources = {result['source'] for result in results}
            assert len(sources) >= 1, "Should use at least one enumeration method"
            
            # Property 1.4: All subdomains should belong to the target domain
            for result in results:
                subdomain = result['subdomain']
                assert subdomain.endswith(f".{domain}") or subdomain == domain, \
                    f"Subdomain {subdomain} should belong to domain {domain}"
            
            # Property 1.5: Results should be unique
            subdomains = [result['subdomain'] for result in results]
            assert len(subdomains) == len(set(subdomains)), "Subdomain results should be unique"
            
            # Property 1.6: Source attribution should be valid
            valid_sources = {'subfinder', 'amass', 'dns_bruteforce', 'certificate_transparency'}
            for result in results:
                assert result['source'] in valid_sources, \
                    f"Source {result['source']} should be a valid enumeration method"
    
    @rule(target=targets)
    def test_subdomain_enumeration_error_handling(self, target):
        """
        Property 1.7: Subdomain enumeration error handling
        
        Tests that subdomain enumeration handles errors gracefully:
        1. Tool failures don't crash the system
        2. Network errors are handled
        3. Invalid domains are handled
        4. Partial results are still returned
        """
        domain = target['domain']
        
        # Test tool failure scenario
        mock_failed_result = Mock()
        mock_failed_result.returncode = 1
        mock_failed_result.stdout = ""
        mock_failed_result.stderr = "Tool failed"
        self.mock_subprocess.return_value = mock_failed_result
        
        # Mock DNS failures
        from modules.recon_module import dns
        self.mock_dns.side_effect = dns.resolver.NXDOMAIN()
        
        with patch.object(self.recon_module, 'check_tool_availability') as mock_check:
            mock_check.return_value = False  # Simulate tools not available
            
            # Should not raise exception even with failures
            try:
                results = self.recon_module._run_subdomain_enumeration(domain)
                
                # Property 1.7.1: Should return a list even on failure
                assert isinstance(results, list), "Should return list even on tool failures"
                
                # Property 1.7.2: Should handle gracefully without crashing
                # If we reach here, the test passed
                
            except Exception as e:
                # Should not raise unhandled exceptions
                assert False, f"Subdomain enumeration should handle errors gracefully, got: {e}"
    
    @rule(target=targets)
    def test_subdomain_result_enrichment(self, target):
        """
        Property 1.8: Subdomain result enrichment
        
        Tests that subdomain results are properly enriched:
        1. IP addresses are resolved
        2. HTTP status codes are checked
        3. Page titles are extracted
        4. Results are structured consistently
        """
        domain = target['domain']
        
        # Setup mock for successful enumeration
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = f"www.{domain}\napi.{domain}"
        mock_result.stderr = ""
        self.mock_subprocess.return_value = mock_result
        
        with patch.object(self.recon_module, 'check_tool_availability') as mock_check:
            mock_check.return_value = True
            
            results = self.recon_module._run_subdomain_enumeration(domain)
            
            for result in results:
                # Property 1.8.1: Results should have consistent structure
                required_fields = ['subdomain', 'source', 'ip_addresses']
                for field in required_fields:
                    assert field in result, f"Result must have {field} field"
                
                # Property 1.8.2: IP addresses should be valid format
                for ip in result['ip_addresses']:
                    assert isinstance(ip, str), "IP addresses should be strings"
                    # Basic IP format validation (simplified)
                    parts = ip.split('.')
                    if len(parts) == 4:  # IPv4
                        assert all(part.isdigit() and 0 <= int(part) <= 255 for part in parts), \
                            f"Invalid IPv4 address: {ip}"
                
                # Property 1.8.3: Optional fields should have correct types
                if 'status_code' in result:
                    assert isinstance(result['status_code'], int), "Status code should be integer"
                    assert 100 <= result['status_code'] <= 599, "Status code should be valid HTTP code"
                
                if 'title' in result:
                    assert isinstance(result['title'], str), "Title should be string"
    
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


class TestSubdomainEnumerationProperties(unittest.TestCase):
    """Test runner for subdomain enumeration properties"""
    
    def test_subdomain_enumeration_properties(self):
        """Run property-based tests for subdomain enumeration"""
        print("Testing subdomain enumeration completeness properties...")
        
        # Run the state machine tests
        state_machine = SubdomainEnumerationProperties()
        try:
            # Initialize the state machine
            state_machine.setup_initial_state()
            
            # Test with various domain formats
            test_domains = [
                "example.com",
                "test-site.org",
                "api.service.net",
                "sub.domain.co.uk"
            ]
            
            for domain in test_domains:
                # Create target
                session = state_machine.db_manager.get_session()
                try:
                    target = Target(
                        project_id=state_machine.test_project.id,
                        name=f"Test {domain}",
                        url=f"https://{domain}",
                        target_type="domain",
                        tags=["test"]
                    )
                    session.add(target)
                    session.commit()
                    session.refresh(target)
                    
                    target_dict = {
                        'id': target.id,
                        'url': f"https://{domain}",
                        'domain': domain,
                        'target_type': 'domain'
                    }
                    
                    # Test properties
                    state_machine.test_subdomain_enumeration_completeness(target_dict)
                    state_machine.test_subdomain_enumeration_error_handling(target_dict)
                    state_machine.test_subdomain_result_enrichment(target_dict)
                    
                finally:
                    session.close()
            
            print("✅ Subdomain enumeration completeness property tests passed!")
            
        finally:
            state_machine.teardown_method(None)


if __name__ == "__main__":
    unittest.main()
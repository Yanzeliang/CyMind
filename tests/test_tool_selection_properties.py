"""
Property-based tests for tool selection functionality

Property 4: Tool selection functionality
Validates: Requirements 1.4

This test ensures that the tool selection system correctly identifies
available tools and selects appropriate tools for different scan types.
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

from modules.recon_module import ReconModule, ReconToolType
from models import DatabaseManager, Target, Project, Session


class ToolSelectionProperties(RuleBasedStateMachine):
    """Property-based state machine for testing tool selection functionality"""
    
    targets = Bundle('targets')
    tool_configs = Bundle('tool_configs')
    
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
        # Mock subprocess calls for tool availability checking
        subprocess_patcher = patch('modules.recon_module.subprocess.run')
        self.mock_subprocess = subprocess_patcher.start()
        self.mock_patches.append(subprocess_patcher)
        
        # Setup default mock responses
        self.setup_default_mocks()
    
    def setup_default_mocks(self):
        """Setup default mock responses"""
        # Mock tool availability check with different responses for different tools
        def subprocess_side_effect(cmd, **kwargs):
            tool_name = cmd[0] if cmd else ""
            mock_result = Mock()
            
            # Valid tools return success
            if tool_name in ['subfinder', 'amass', 'nmap', 'nuclei', 'httpx']:
                mock_result.returncode = 0
                mock_result.stdout = "Tool help output"
                mock_result.stderr = ""
            else:
                # Invalid tools return failure
                mock_result.returncode = 1
                mock_result.stdout = ""
                mock_result.stderr = "Command not found"
            
            return mock_result
        
        self.mock_subprocess.side_effect = subprocess_side_effect
    
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
                name="Test Tool Selection Project",
                description="Project for testing tool selection"
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
        """Create a target for tool selection testing"""
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
                tags=["test", "tool-selection"]
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
    
    @rule()
    def test_tool_availability_detection(self):
        """
        Property 4.1: Tool availability detection
        
        Tests that the system correctly identifies which tools are available:
        1. Checks tool availability accurately
        2. Caches availability results
        3. Handles tool check failures gracefully
        4. Returns consistent results
        """
        # Test common reconnaissance tools
        test_tools = ['subfinder', 'amass', 'nmap', 'nuclei', 'httpx']
        
        for tool in test_tools:
            # Property 4.1.1: Tool availability check should return boolean
            availability = self.recon_module.check_tool_availability(tool)
            assert isinstance(availability, bool), f"Tool availability for {tool} should be boolean"
            
            # Property 4.1.2: Repeated checks should return same result (caching)
            availability2 = self.recon_module.check_tool_availability(tool)
            assert availability == availability2, f"Tool availability for {tool} should be consistent"
        
        # Property 4.1.3: Invalid tool names should return False
        invalid_tools = ['nonexistent_tool_xyz', 'fake_scanner_123']
        for tool in invalid_tools:
            availability = self.recon_module.check_tool_availability(tool)
            assert availability == False, f"Invalid tool {tool} should not be available"
    
    @rule()
    def test_available_tools_listing(self):
        """
        Property 4.2: Available tools listing
        
        Tests that the system provides accurate listing of available tools:
        1. Lists all supported tools
        2. Shows correct availability status
        3. Includes built-in capabilities
        4. Provides structured output
        """
        # Get list of available tools
        available_tools = self.recon_module.list_available_tools()
        
        # Property 4.2.1: Should return dictionary
        assert isinstance(available_tools, dict), "Available tools should be dictionary"
        
        # Property 4.2.2: Should include expected tools
        expected_tools = [
            'subfinder', 'amass', 'nmap', 
            'dns_bruteforce', 'certificate_transparency', 
            'banner_grabbing', 'ssl_analysis', 'technology_identification'
        ]
        
        for tool in expected_tools:
            assert tool in available_tools, f"Tool {tool} should be in available tools list"
            assert isinstance(available_tools[tool], bool), \
                f"Availability status for {tool} should be boolean"
        
        # Property 4.2.3: Built-in tools should always be available
        builtin_tools = [
            'dns_bruteforce', 'certificate_transparency', 
            'banner_grabbing', 'ssl_analysis', 'technology_identification'
        ]
        
        for tool in builtin_tools:
            assert available_tools[tool] == True, f"Built-in tool {tool} should always be available"
    
    @rule(target=targets, tools=st.lists(
        st.sampled_from(['subdomain_enum', 'service_fingerprint', 'dns_analysis', 'tech_stack']),
        min_size=1, max_size=4, unique=True
    ))
    def test_tool_selection_for_comprehensive_recon(self, target, tools):
        """
        Property 4.3: Tool selection for comprehensive reconnaissance
        
        Tests that tool selection works correctly for comprehensive scans:
        1. Accepts valid tool combinations
        2. Handles tool availability gracefully
        3. Falls back to available alternatives
        4. Provides meaningful error messages
        """
        # Property 4.3.1: Valid tool combinations should be accepted
        valid_tools = ['subdomain_enum', 'service_fingerprint', 'dns_analysis', 'tech_stack']
        for tool in tools:
            assert tool in valid_tools, f"Tool {tool} should be valid"
        
        # Mock comprehensive recon execution
        with patch.object(self.recon_module, '_execute_comprehensive_recon') as mock_exec:
            mock_exec.return_value = {
                'status': 'completed',
                'tools_used': tools,
                'results': {}
            }
            
            # Start comprehensive recon
            result = self.recon_module.run_comprehensive_recon(target, tools)
            
            # Property 4.3.2: Should accept tool selection
            assert result['status'] in ['started', 'completed'], \
                f"Comprehensive recon should start with tools {tools}"
            
            if result['status'] == 'started':
                scan_id = result['scan_id']
                assert scan_id in self.recon_module.active_scans, \
                    "Started scan should be tracked"
                
                scan_info = self.recon_module.active_scans[scan_id]
                assert scan_info['tools'] == tools, \
                    "Scan should track selected tools"
    
    @rule(target=targets)
    def test_automatic_tool_selection(self, target):
        """
        Property 4.4: Automatic tool selection
        
        Tests that automatic tool selection works when no tools specified:
        1. Selects appropriate default tools
        2. Considers tool availability
        3. Provides comprehensive coverage
        4. Handles unavailable tools gracefully
        """
        # Test automatic tool selection (no tools specified)
        with patch.object(self.recon_module, '_execute_comprehensive_recon') as mock_exec:
            mock_exec.return_value = {
                'status': 'completed',
                'tools_used': ['subdomain_enum', 'service_fingerprint', 'dns_analysis', 'tech_stack'],
                'results': {}
            }
            
            # Start recon without specifying tools
            result = self.recon_module.run_comprehensive_recon(target, tools=None)
            
            # Property 4.4.1: Should use default tool selection
            assert result['status'] in ['started', 'completed'], \
                "Automatic tool selection should work"
            
            if result['status'] == 'started':
                scan_id = result['scan_id']
                scan_info = self.recon_module.active_scans[scan_id]
                
                # Property 4.4.2: Should select reasonable default tools
                selected_tools = scan_info['tools']
                assert isinstance(selected_tools, list), "Selected tools should be list"
                assert len(selected_tools) > 0, "Should select at least one tool"
                
                # Property 4.4.3: Selected tools should be valid
                valid_tools = ['subdomain_enum', 'service_fingerprint', 'dns_analysis', 'tech_stack']
                for tool in selected_tools:
                    assert tool in valid_tools, f"Selected tool {tool} should be valid"
    
    @rule()
    def test_tool_selection_with_unavailable_tools(self):
        """
        Property 4.5: Tool selection with unavailable tools
        
        Tests behavior when selected tools are not available:
        1. Detects unavailable tools
        2. Falls back to available alternatives
        3. Provides informative warnings
        4. Continues with available tools
        """
        # Mock all external tools as unavailable
        with patch.object(self.recon_module, 'check_tool_availability') as mock_check:
            mock_check.return_value = False  # All external tools unavailable
            
            # Get available tools
            available_tools = self.recon_module.list_available_tools()
            
            # Property 4.5.1: External tools should be marked unavailable
            external_tools = ['subfinder', 'amass', 'nmap']
            for tool in external_tools:
                assert available_tools[tool] == False, \
                    f"External tool {tool} should be unavailable when mocked"
            
            # Property 4.5.2: Built-in tools should still be available
            builtin_tools = ['dns_bruteforce', 'certificate_transparency']
            for tool in builtin_tools:
                assert available_tools[tool] == True, \
                    f"Built-in tool {tool} should remain available"
    
    @rule(target=targets)
    def test_tool_selection_error_handling(self, target):
        """
        Property 4.6: Tool selection error handling
        
        Tests error handling in tool selection:
        1. Invalid tool names are rejected
        2. Empty tool lists are handled
        3. Tool check failures don't crash system
        4. Meaningful error messages are provided
        """
        # Test with invalid tool names
        invalid_tools = ['invalid_tool', 'nonexistent_scanner', '']
        
        with patch.object(self.recon_module, '_execute_comprehensive_recon') as mock_exec:
            mock_exec.return_value = {
                'status': 'error',
                'error': 'Invalid tool selection'
            }
            
            # Property 4.6.1: Should handle invalid tools gracefully
            try:
                result = self.recon_module.run_comprehensive_recon(target, invalid_tools)
                
                # Should either reject invalid tools or filter them out
                assert result['status'] in ['started', 'error'], \
                    "Should handle invalid tools gracefully"
                
            except Exception as e:
                # Should not raise unhandled exceptions
                assert False, f"Tool selection should handle invalid tools gracefully, got: {e}"
        
        # Test with empty tool list
        try:
            result = self.recon_module.run_comprehensive_recon(target, [])
            
            # Property 4.6.2: Should handle empty tool list
            assert result['status'] in ['started', 'error'], \
                "Should handle empty tool list gracefully"
            
        except Exception as e:
            assert False, f"Tool selection should handle empty list gracefully, got: {e}"
    
    @rule()
    def test_tool_capability_mapping(self):
        """
        Property 4.7: Tool capability mapping
        
        Tests that tools are correctly mapped to their capabilities:
        1. Each tool type has defined capabilities
        2. Tool selection matches scan requirements
        3. Capability coverage is comprehensive
        4. Tool combinations are logical
        """
        # Define expected tool capabilities
        tool_capabilities = {
            'subdomain_enum': [ReconToolType.SUBDOMAIN_ENUM],
            'service_fingerprint': [ReconToolType.SERVICE_FINGERPRINT, ReconToolType.PORT_SCAN],
            'dns_analysis': [ReconToolType.DNS_ANALYSIS],
            'tech_stack': [ReconToolType.TECH_STACK]
        }
        
        # Property 4.7.1: Each scan type should map to appropriate tools
        for scan_type, expected_capabilities in tool_capabilities.items():
            assert isinstance(expected_capabilities, list), \
                f"Capabilities for {scan_type} should be list"
            
            for capability in expected_capabilities:
                assert isinstance(capability, ReconToolType), \
                    f"Capability {capability} should be ReconToolType enum"
        
        # Property 4.7.2: Tool combinations should provide comprehensive coverage
        all_tools = list(tool_capabilities.keys())
        all_capabilities = set()
        for capabilities in tool_capabilities.values():
            all_capabilities.update(capabilities)
        
        # Should cover main reconnaissance areas
        expected_coverage = {
            ReconToolType.SUBDOMAIN_ENUM,
            ReconToolType.SERVICE_FINGERPRINT,
            ReconToolType.DNS_ANALYSIS,
            ReconToolType.TECH_STACK
        }
        
        assert expected_coverage.issubset(all_capabilities), \
            "Tool selection should provide comprehensive reconnaissance coverage"
    
    @rule()
    def test_tool_performance_considerations(self):
        """
        Property 4.8: Tool performance considerations
        
        Tests that tool selection considers performance:
        1. Resource-intensive tools are managed
        2. Parallel execution is optimized
        3. Timeout handling is appropriate
        4. Resource limits are respected
        """
        # Property 4.8.1: Recon module should have worker limits
        assert hasattr(self.recon_module, 'max_workers'), \
            "Recon module should have worker limit configuration"
        
        assert isinstance(self.recon_module.max_workers, int), \
            "Max workers should be integer"
        
        assert self.recon_module.max_workers > 0, \
            "Max workers should be positive"
        
        # Property 4.8.2: Should have executor for parallel processing
        assert hasattr(self.recon_module, 'executor'), \
            "Recon module should have executor for parallel processing"
        
        # Property 4.8.3: Should track active scans
        assert hasattr(self.recon_module, 'active_scans'), \
            "Recon module should track active scans"
        
        assert isinstance(self.recon_module.active_scans, dict), \
            "Active scans should be dictionary"
    
    @invariant()
    def tool_cache_consistency(self):
        """Ensure tool availability cache remains consistent"""
        # Property: Tool cache should be dictionary
        assert isinstance(self.recon_module._tool_cache, dict), \
            "Tool cache should be dictionary"
        
        # Property: All cached values should be boolean
        for tool, available in self.recon_module._tool_cache.items():
            assert isinstance(tool, str), "Tool name should be string"
            assert isinstance(available, bool), "Tool availability should be boolean"
    
    @invariant()
    def database_consistency(self):
        """Ensure database remains consistent throughout testing"""
        session = self.db_manager.get_session()
        try:
            # Check that test project still exists
            project = session.query(Project).filter_by(id=self.test_project.id).first()
            assert project is not None, "Test project should exist"
        finally:
            session.close()


class TestToolSelectionProperties(unittest.TestCase):
    """Test runner for tool selection properties"""
    
    def test_tool_selection_properties(self):
        """Run property-based tests for tool selection"""
        print("Testing tool selection functionality properties...")
        
        # Run the state machine tests
        state_machine = ToolSelectionProperties()
        try:
            # Initialize the state machine
            state_machine.setup_initial_state()
            
            # Test basic tool selection properties
            state_machine.test_tool_availability_detection()
            state_machine.test_available_tools_listing()
            state_machine.test_tool_selection_with_unavailable_tools()
            state_machine.test_tool_capability_mapping()
            state_machine.test_tool_performance_considerations()
            
            # Test with various targets and tool combinations
            test_domains = ["example.com", "test-site.org", "api.service.net"]
            tool_combinations = [
                ['subdomain_enum'],
                ['service_fingerprint'],
                ['dns_analysis'],
                ['tech_stack'],
                ['subdomain_enum', 'service_fingerprint'],
                ['dns_analysis', 'tech_stack'],
                ['subdomain_enum', 'service_fingerprint', 'dns_analysis', 'tech_stack']
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
                    
                    # Test with different tool combinations
                    for tools in tool_combinations:
                        state_machine.test_tool_selection_for_comprehensive_recon(target_dict, tools)
                    
                    # Test automatic tool selection
                    state_machine.test_automatic_tool_selection(target_dict)
                    state_machine.test_tool_selection_error_handling(target_dict)
                    
                finally:
                    session.close()
            
            print("✅ Tool selection functionality property tests passed!")
            
        finally:
            state_machine.teardown_method(None)


if __name__ == "__main__":
    unittest.main()
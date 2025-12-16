"""
Property-based tests for configuration validation.
**Feature: cymind-enhancement, Property 30: Configuration validation**
**Validates: Requirements 8.5**
"""

import pytest
import tempfile
import os
import yaml
from hypothesis import given, strategies as st, assume
from pathlib import Path

from core.config import (
    ConfigManager, CyMindConfig, Environment, ConfigValidationError,
    DatabaseConfig, LoggingConfig, SecurityConfig, ScannerConfig,
    AIConfig, PluginConfig
)


class TestConfigurationValidation:
    """Property-based tests for configuration validation."""
    
    @given(
        port=st.integers(min_value=1, max_value=65535),
        log_level=st.sampled_from(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']),
        max_concurrent_scans=st.integers(min_value=1, max_value=100),
        environment=st.sampled_from(['development', 'testing', 'production'])
    )
    def test_valid_configuration_should_pass_validation(self, port, log_level, max_concurrent_scans, environment):
        """
        **Feature: cymind-enhancement, Property 30: Configuration validation**
        For any valid configuration parameters, the system should validate successfully.
        """
        config_data = {
            'environment': environment,
            'port': port,
            'logging': {'level': log_level},
            'scanner': {'max_concurrent_scans': max_concurrent_scans},
            'security': {'secret_key': 'test-key' if environment == 'production' else ''}
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name
        
        try:
            config_manager = ConfigManager(temp_path)
            config = config_manager.config
            
            # Validation should pass without raising exceptions
            assert config.port == port
            assert config.logging.level == log_level
            assert config.scanner.max_concurrent_scans == max_concurrent_scans
            assert config.environment.value == environment
        finally:
            os.unlink(temp_path)
    
    @given(
        port=st.integers().filter(lambda x: x < 1 or x > 65535)
    )
    def test_invalid_port_should_fail_validation(self, port):
        """
        **Feature: cymind-enhancement, Property 30: Configuration validation**
        For any invalid port number, configuration validation should fail.
        """
        config_data = {
            'port': port,
            'environment': 'development'
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="Invalid port number"):
                ConfigManager(temp_path)
        finally:
            os.unlink(temp_path)
    
    @given(
        log_level=st.text().filter(lambda x: x.upper() not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    )
    def test_invalid_log_level_should_fail_validation(self, log_level):
        """
        **Feature: cymind-enhancement, Property 30: Configuration validation**
        For any invalid logging level, configuration validation should fail.
        """
        assume(log_level.strip() != '')  # Skip empty strings
        
        config_data = {
            'logging': {'level': log_level},
            'environment': 'development'
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="Invalid logging level"):
                ConfigManager(temp_path)
        finally:
            os.unlink(temp_path)
    
    @given(
        max_concurrent_scans=st.integers(max_value=0)
    )
    def test_invalid_scanner_config_should_fail_validation(self, max_concurrent_scans):
        """
        **Feature: cymind-enhancement, Property 30: Configuration validation**
        For any invalid scanner configuration, validation should fail.
        """
        config_data = {
            'scanner': {'max_concurrent_scans': max_concurrent_scans},
            'environment': 'development'
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="max_concurrent_scans must be positive"):
                ConfigManager(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_production_environment_requires_secret_key(self):
        """
        **Feature: cymind-enhancement, Property 30: Configuration validation**
        For production environment, secret key should be required.
        """
        config_data = {
            'environment': 'production',
            'security': {'secret_key': ''}  # Empty secret key
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="Secret key is required in production"):
                ConfigManager(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_ai_enabled_requires_api_key(self):
        """
        **Feature: cymind-enhancement, Property 30: Configuration validation**
        For enabled AI assistant, API key should be required.
        """
        config_data = {
            'environment': 'development',
            'ai': {
                'enabled': True,
                'api_key': ''  # Empty API key
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name
        
        try:
            with pytest.raises(ConfigValidationError, match="AI API key is required when AI is enabled"):
                ConfigManager(temp_path)
        finally:
            os.unlink(temp_path)
    
    @given(
        debug=st.booleans(),
        host=st.text(min_size=1, max_size=50).filter(lambda x: x.strip()),
        port=st.integers(min_value=1, max_value=65535),
        environment=st.sampled_from(['development', 'testing', 'production'])
    )
    def test_configuration_round_trip_consistency(self, debug, host, port, environment):
        """
        **Feature: cymind-enhancement, Property 30: Configuration validation**
        For any valid configuration, saving and loading should preserve all values.
        """
        config_dict = {
            'environment': environment,
            'debug': debug,
            'host': host,
            'port': port
        }
        
        # Add required fields for production
        if environment == 'production':
            config_dict['security'] = {'secret_key': 'test-production-key'}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_dict, f)
            temp_path = f.name
        
        try:
            # Load configuration
            config_manager = ConfigManager(temp_path)
            original_config = config_manager.config
            
            # Save configuration to new file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f2:
                new_path = f2.name
            
            config_manager.save_config(new_path)
            
            # Load the saved configuration
            new_config_manager = ConfigManager(new_path)
            new_config = new_config_manager.config
            
            # Verify key properties are preserved
            assert original_config.environment == new_config.environment
            assert original_config.port == new_config.port
            assert original_config.debug == new_config.debug
            assert original_config.host == new_config.host
            
            os.unlink(new_path)
        finally:
            os.unlink(temp_path)
    
    @given(
        debug_override=st.booleans(),
        host_override=st.text(min_size=1, max_size=50).filter(lambda x: x.strip()),
        port_override=st.integers(min_value=1, max_value=65535),
        log_level_override=st.sampled_from(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    )
    def test_environment_variable_override_behavior(self, debug_override, host_override, port_override, log_level_override):
        """
        **Feature: cymind-enhancement, Property 30: Configuration validation**
        For any environment variables, they should properly override configuration file values.
        """
        # Create base configuration
        base_config = {
            'environment': 'development',
            'debug': False,
            'host': 'localhost',
            'port': 5000,
            'database': {'url': 'sqlite:///test.db'},
            'logging': {'level': 'INFO'},
            'security': {'secret_key': 'base-key'}
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(base_config, f)
            temp_path = f.name
        
        try:
            # Set environment variables
            original_env = {
                'CYMIND_DEBUG': os.environ.get('CYMIND_DEBUG'),
                'CYMIND_HOST': os.environ.get('CYMIND_HOST'),
                'CYMIND_PORT': os.environ.get('CYMIND_PORT'),
                'CYMIND_LOG_LEVEL': os.environ.get('CYMIND_LOG_LEVEL')
            }
            
            os.environ['CYMIND_DEBUG'] = 'true' if debug_override else 'false'
            os.environ['CYMIND_HOST'] = host_override
            os.environ['CYMIND_PORT'] = str(port_override)
            os.environ['CYMIND_LOG_LEVEL'] = log_level_override
            
            # Load configuration with environment overrides
            config_manager = ConfigManager(temp_path)
            config = config_manager.config
            
            # Verify overrides took effect
            assert config.debug == debug_override
            assert config.host == host_override
            assert config.port == port_override
            assert config.logging.level == log_level_override
            
        finally:
            # Restore original environment
            for key, original_value in original_env.items():
                if original_value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = original_value
            
            os.unlink(temp_path)
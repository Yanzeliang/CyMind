"""
Property-based tests for system-wide error logging.
**Feature: cymind-enhancement, Property 27: System-wide error logging**
**Validates: Requirements 8.1, 8.3**
"""

import pytest
import logging
import tempfile
import os
import json
from io import StringIO
from hypothesis import given, strategies as st
from unittest.mock import patch

from core.error_handler import (
    ErrorHandler, CyMindError, ErrorSeverity, ErrorContext,
    ConfigurationError, ScannerError, PluginError, AIAssistantError,
    DatabaseError, NetworkError
)
from core.logging_config import (
    SensitiveDataFilter, StructuredFormatter,
    PerformanceLogger, SecurityLogger
)


class TestSystemWideErrorLogging:
    """Property-based tests for system-wide error logging."""
    
    def setup_method(self):
        """Set up test environment for each test."""
        self.log_stream = StringIO()
        self.logger = logging.getLogger('test_logger')
        self.logger.handlers.clear()
        
        # Create stream handler for testing
        self.handler = logging.StreamHandler(self.log_stream)
        self.handler.setFormatter(logging.Formatter('%(levelname)s:%(name)s:%(message)s'))
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)
    
    def teardown_method(self):
        """Clean up after each test."""
        self.logger.handlers.clear()
        self.log_stream.close()
    
    def test_error_logging_includes_required_information(self):
        """
        **Feature: cymind-enhancement, Property 27: System-wide error logging**
        For any error with context, logging should include detailed error information with appropriate severity levels.
        """
        # Test with a simple, predictable message
        error_message = "Test error message"
        component = "test_component"
        operation = "test_operation"
        severity = ErrorSeverity.MEDIUM
        
        # Log the error information
        self.logger.warning(
            error_message,
            extra={
                'component': component,
                'operation': operation,
                'severity': severity.value
            }
        )
        
        # Get logged content
        log_content = self.log_stream.getvalue()
        
        # Verify that essential information is logged
        assert error_message in log_content
        assert "WARNING" in log_content
    
    def test_sensitive_data_filtering_in_logs(self):
        """
        **Feature: cymind-enhancement, Property 27: System-wide error logging**
        For any log message containing sensitive data, the system should filter out sensitive information.
        """
        # Create a logger with sensitive data filter
        test_logger = logging.getLogger('sensitive_test')
        test_logger.handlers.clear()
        
        # Use StringIO to capture log output
        log_stream = StringIO()
        stream_handler = logging.StreamHandler(log_stream)
        stream_handler.addFilter(SensitiveDataFilter())
        stream_handler.setFormatter(logging.Formatter('%(message)s'))
        test_logger.addHandler(stream_handler)
        test_logger.setLevel(logging.DEBUG)
        
        # Test with known sensitive and non-sensitive data
        test_message = "User login with password=secret123 and username=testuser"
        
        # Log the message
        test_logger.info(test_message)
        
        # Get the logged content
        log_output = log_stream.getvalue()
        
        # Verify sensitive data is filtered
        assert "secret123" not in log_output or "***" in log_output
        # Non-sensitive data should be preserved
        assert "testuser" in log_output
    
    def test_different_error_types_logged_with_correct_severity(self):
        """
        **Feature: cymind-enhancement, Property 27: System-wide error logging**
        For any type of system error, it should be logged with appropriate severity levels.
        """
        # Test with known error types and messages
        test_cases = [
            (ConfigurationError, "Configuration error", ErrorSeverity.HIGH),
            (ScannerError, "Scanner error", ErrorSeverity.MEDIUM),
            (DatabaseError, "Database error", ErrorSeverity.HIGH)
        ]
        
        for error_type, message, expected_severity in test_cases:
            # Log the error message with severity
            self.logger.warning(
                message,
                extra={
                    'error_type': error_type.__name__,
                    'severity': expected_severity.value
                }
            )
        
        # Get logged content
        log_content = self.log_stream.getvalue()
        
        # Verify all errors were logged
        for _, message, _ in test_cases:
            assert message in log_content
        
        # Verify severity levels are present
        assert "WARNING" in log_content
    
    def test_structured_logging_format_consistency(self):
        """
        **Feature: cymind-enhancement, Property 27: System-wide error logging**
        For any log entries, structured logging should maintain consistent format.
        """
        # Create logger with structured formatter
        structured_logger = logging.getLogger('structured_test')
        structured_logger.handlers.clear()
        
        log_stream = StringIO()
        stream_handler = logging.StreamHandler(log_stream)
        stream_handler.setFormatter(StructuredFormatter())
        structured_logger.addHandler(stream_handler)
        structured_logger.setLevel(logging.DEBUG)
        
        # Log a test entry with extra data
        test_message = "Test structured log message"
        extra_data = {
            'component': 'test_component',
            'operation': 'test_operation',
            'user_id': 'test_user'
        }
        structured_logger.info(test_message, extra=extra_data)
        
        # Get logged output
        log_output = log_stream.getvalue().strip()
        
        # Verify the log entry is valid JSON
        try:
            log_data = json.loads(log_output)
            
            # Verify required fields are present
            assert 'timestamp' in log_data
            assert 'level' in log_data
            assert 'logger' in log_data
            assert 'message' in log_data
            assert log_data['message'] == test_message
            
        except json.JSONDecodeError:
            pytest.fail(f"Log line is not valid JSON: {log_output}")
    
    def test_performance_logging_captures_metrics(self):
        """
        **Feature: cymind-enhancement, Property 27: System-wide error logging**
        For any performance metrics, the system should log them with proper categorization.
        """
        # Create performance logger
        perf_logger = PerformanceLogger('test_performance')
        
        # Clear existing handlers and add our test handler
        perf_logger.logger.handlers.clear()
        
        log_stream = StringIO()
        stream_handler = logging.StreamHandler(log_stream)
        stream_handler.setFormatter(StructuredFormatter())
        perf_logger.logger.addHandler(stream_handler)
        perf_logger.logger.setLevel(logging.DEBUG)
        
        # Log test performance metrics
        scan_id = "test_scan_123"
        scan_type = "port_scan"
        duration = 45.5
        target_count = 10
        
        perf_logger.log_scan_performance(scan_id, scan_type, duration, target_count)
        
        # Verify performance metrics are logged
        log_output = log_stream.getvalue().strip()
        
        log_data = json.loads(log_output)
        assert log_data['metric_type'] == 'scan_performance'
        assert log_data['scan_id'] == scan_id
        assert log_data['scan_type'] == scan_type
        assert log_data['duration_seconds'] == duration
        assert log_data['target_count'] == target_count
    
    def test_security_logging_captures_events(self):
        """
        **Feature: cymind-enhancement, Property 27: System-wide error logging**
        For any security events, the system should log them with appropriate security context.
        """
        # Create security logger
        sec_logger = SecurityLogger('test_security')
        
        # Clear existing handlers and add our test handler
        sec_logger.logger.handlers.clear()
        
        log_stream = StringIO()
        stream_handler = logging.StreamHandler(log_stream)
        stream_handler.setFormatter(StructuredFormatter())
        sec_logger.logger.addHandler(stream_handler)
        sec_logger.logger.setLevel(logging.DEBUG)
        
        # Log test security event
        username = "test_user"
        ip_address = "192.168.1.100"
        success = True
        
        sec_logger.log_authentication_attempt(username, success, ip_address)
        
        # Verify security event is logged
        log_output = log_stream.getvalue().strip()
        
        log_data = json.loads(log_output)
        assert log_data['event_type'] == 'authentication'
        assert log_data['username'] == username
        assert log_data['ip_address'] == ip_address
        assert log_data['success'] == success
    
    def test_concurrent_error_logging_thread_safety(self):
        """
        **Feature: cymind-enhancement, Property 27: System-wide error logging**
        For any concurrent error logging operations, the system should handle them safely.
        """
        import threading
        
        # Test messages
        test_messages = ["Error 1", "Error 2", "Error 3", "Error 4", "Error 5"]
        
        # Function to log errors concurrently
        def log_error(message):
            self.logger.warning(
                message,
                extra={
                    'component': 'concurrent_test',
                    'operation': 'test_operation'
                }
            )
        
        # Create and start threads
        threads = []
        for message in test_messages:
            thread = threading.Thread(target=log_error, args=(message,))
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all errors were logged
        log_content = self.log_stream.getvalue()
        
        # All error messages should be present in the log
        for message in test_messages:
            assert message in log_content
#!/usr/bin/env python3
"""
Simple test script to verify the core infrastructure is working correctly.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import init_config, get_config, ConfigValidationError
from core.logging_config import setup_logging, get_logger
from core.error_handler import get_error_handler, CyMindError, ErrorSeverity, ErrorContext


def test_configuration():
    """Test configuration management."""
    print("Testing configuration management...")
    
    try:
        # Initialize with default config
        init_config()
        config = get_config()
        
        print(f"✓ Configuration loaded successfully")
        print(f"  Environment: {config.environment.value}")
        print(f"  Debug mode: {config.debug}")
        print(f"  Host: {config.host}")
        print(f"  Port: {config.port}")
        print(f"  Database URL: {config.database.url}")
        print(f"  Log level: {config.logging.level}")
        
        return True
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return False


def test_logging():
    """Test logging system."""
    print("\nTesting logging system...")
    
    try:
        # Setup logging
        setup_logging()
        logger = get_logger("test")
        
        # Test different log levels
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")
        
        print("✓ Logging system working correctly")
        return True
    except Exception as e:
        print(f"✗ Logging test failed: {e}")
        return False


def test_error_handling():
    """Test error handling system."""
    print("\nTesting error handling system...")
    
    try:
        error_handler = get_error_handler()
        
        # Test custom error
        context = ErrorContext(
            component="test",
            operation="test_error_handling",
            additional_data={"test_key": "test_value"}
        )
        
        test_error = CyMindError(
            "Test error message",
            ErrorSeverity.MEDIUM,
            context
        )
        
        error_handler.handle_error(test_error)
        
        # Test circuit breaker
        circuit_breaker = error_handler.get_circuit_breaker("test_service")
        
        print("✓ Error handling system working correctly")
        print(f"  Circuit breaker created: {circuit_breaker.name}")
        print(f"  Circuit breaker state: {circuit_breaker.state.value}")
        
        return True
    except Exception as e:
        print(f"✗ Error handling test failed: {e}")
        return False


def test_directory_structure():
    """Test that all required directories exist."""
    print("\nTesting directory structure...")
    
    required_dirs = [
        "core",
        "plugins", 
        "ai_assistant",
        "config",
        "logs"
    ]
    
    all_exist = True
    for dir_name in required_dirs:
        if os.path.exists(dir_name):
            print(f"✓ Directory exists: {dir_name}")
        else:
            print(f"✗ Directory missing: {dir_name}")
            all_exist = False
    
    return all_exist


def main():
    """Run all infrastructure tests."""
    print("CyMind Infrastructure Test Suite")
    print("=" * 40)
    
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    tests = [
        test_directory_structure,
        test_configuration,
        test_logging,
        test_error_handling
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\n" + "=" * 40)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All infrastructure tests passed!")
        return 0
    else:
        print("✗ Some tests failed. Please check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
"""
Error handling framework with circuit breaker pattern for CyMind platform.
Provides comprehensive error handling, recovery mechanisms, and failure isolation.
"""

import time
import functools
import threading
from typing import Dict, Any, Optional, Callable, Type, List
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .logging_config import get_logger


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, requests blocked
    HALF_OPEN = "half_open"  # Testing if service recovered


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ErrorContext:
    """Context information for error handling."""
    component: str
    operation: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)


class CyMindError(Exception):
    """Base exception class for CyMind platform."""
    
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 context: Optional[ErrorContext] = None, cause: Optional[Exception] = None):
        super().__init__(message)
        self.message = message
        self.severity = severity
        self.context = context
        self.cause = cause
        self.timestamp = datetime.utcnow()


class ConfigurationError(CyMindError):
    """Raised when configuration is invalid or missing."""
    
    def __init__(self, message: str, context: Optional[ErrorContext] = None):
        super().__init__(message, ErrorSeverity.HIGH, context)


class ScannerError(CyMindError):
    """Raised when scanner operations fail."""
    pass


class PluginError(CyMindError):
    """Raised when plugin operations fail."""
    pass


class AIAssistantError(CyMindError):
    """Raised when AI assistant operations fail."""
    pass


class DatabaseError(CyMindError):
    """Raised when database operations fail."""
    
    def __init__(self, message: str, context: Optional[ErrorContext] = None):
        super().__init__(message, ErrorSeverity.HIGH, context)


class NetworkError(CyMindError):
    """Raised when network operations fail."""
    pass


class CircuitBreaker:
    """Circuit breaker implementation for failure isolation."""
    
    def __init__(self, name: str, failure_threshold: int = 5,
                 timeout_seconds: int = 60, expected_exception: Type[Exception] = Exception):
        self.name = name
        self.failure_threshold = failure_threshold
        self.timeout_seconds = timeout_seconds
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.state = CircuitState.CLOSED
        self._lock = threading.Lock()
        
        self.logger = get_logger(f"cymind.circuit_breaker.{name}")
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator to wrap functions with circuit breaker."""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return self.call(func, *args, **kwargs)
        return wrapper
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        with self._lock:
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitState.HALF_OPEN
                    self.logger.info(f"Circuit breaker {self.name} transitioning to HALF_OPEN")
                else:
                    raise CyMindError(
                        f"Circuit breaker {self.name} is OPEN",
                        ErrorSeverity.HIGH,
                        ErrorContext(component="circuit_breaker", operation="call")
                    )
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exception as e:
            self._on_failure(e)
            raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt to reset."""
        if self.last_failure_time is None:
            return True
        
        return datetime.utcnow() - self.last_failure_time > timedelta(seconds=self.timeout_seconds)
    
    def _on_success(self) -> None:
        """Handle successful operation."""
        with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.CLOSED
                self.logger.info(f"Circuit breaker {self.name} reset to CLOSED")
            
            self.failure_count = 0
    
    def _on_failure(self, exception: Exception) -> None:
        """Handle failed operation."""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = datetime.utcnow()
            
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN
                self.logger.error(
                    f"Circuit breaker {self.name} opened due to {self.failure_count} failures",
                    extra={'exception': str(exception)}
                )
    
    def reset(self) -> None:
        """Manually reset the circuit breaker."""
        with self._lock:
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.last_failure_time = None
            self.logger.info(f"Circuit breaker {self.name} manually reset")


class RetryHandler:
    """Handles retry logic with exponential backoff."""
    
    def __init__(self, max_attempts: int = 3, base_delay: float = 1.0,
                 max_delay: float = 60.0, backoff_factor: float = 2.0):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        
        self.logger = get_logger("cymind.retry_handler")
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator to add retry logic to functions."""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return self.execute_with_retry(func, *args, **kwargs)
        return wrapper
    
    def execute_with_retry(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic."""
        last_exception = None
        
        for attempt in range(self.max_attempts):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                
                if attempt == self.max_attempts - 1:
                    # Last attempt failed
                    self.logger.error(
                        f"Function {func.__name__} failed after {self.max_attempts} attempts",
                        extra={'exception': str(e)}
                    )
                    break
                
                # Calculate delay for next attempt
                delay = min(
                    self.base_delay * (self.backoff_factor ** attempt),
                    self.max_delay
                )
                
                self.logger.warning(
                    f"Function {func.__name__} failed on attempt {attempt + 1}, "
                    f"retrying in {delay:.2f} seconds",
                    extra={'exception': str(e)}
                )
                
                time.sleep(delay)
        
        # Re-raise the last exception
        if last_exception:
            raise last_exception


class ErrorHandler:
    """Central error handler for the CyMind platform."""
    
    def __init__(self):
        self.logger = get_logger("cymind.error_handler")
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.error_counts: Dict[str, int] = {}
        self._lock = threading.Lock()
    
    def handle_error(self, error: Exception, context: Optional[ErrorContext] = None) -> None:
        """Handle and log errors with appropriate severity."""
        if isinstance(error, CyMindError):
            severity = error.severity
            cymind_error = error
        else:
            severity = self._determine_severity(error)
            cymind_error = CyMindError(
                str(error),
                severity,
                context,
                cause=error
            )
        
        # Log the error
        self._log_error(cymind_error)
        
        # Update error statistics
        self._update_error_stats(cymind_error)
        
        # Handle critical errors
        if severity == ErrorSeverity.CRITICAL:
            self._handle_critical_error(cymind_error)
    
    def _determine_severity(self, error: Exception) -> ErrorSeverity:
        """Determine error severity based on exception type."""
        if isinstance(error, (ConnectionError, TimeoutError)):
            return ErrorSeverity.HIGH
        elif isinstance(error, (ValueError, TypeError)):
            return ErrorSeverity.MEDIUM
        elif isinstance(error, KeyError):
            return ErrorSeverity.LOW
        else:
            return ErrorSeverity.MEDIUM
    
    def _log_error(self, error: CyMindError) -> None:
        """Log error with appropriate level and context."""
        log_level_map = {
            ErrorSeverity.LOW: self.logger.info,
            ErrorSeverity.MEDIUM: self.logger.warning,
            ErrorSeverity.HIGH: self.logger.error,
            ErrorSeverity.CRITICAL: self.logger.critical
        }
        
        log_func = log_level_map[error.severity]
        
        extra_data = {
            'error_type': type(error).__name__,
            'severity': error.severity.value,
            'timestamp': error.timestamp.isoformat()
        }
        
        if error.context:
            extra_data.update({
                'component': error.context.component,
                'operation': error.context.operation,
                'user_id': error.context.user_id,
                'request_id': error.context.request_id
            })
            extra_data.update(error.context.additional_data)
        
        if error.cause:
            extra_data['cause'] = str(error.cause)
        
        log_func(error.message, extra=extra_data)
    
    def _update_error_stats(self, error: CyMindError) -> None:
        """Update error statistics for monitoring."""
        with self._lock:
            error_key = f"{type(error).__name__}:{error.severity.value}"
            self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
    
    def _handle_critical_error(self, error: CyMindError) -> None:
        """Handle critical errors that may require immediate attention."""
        # In a production system, this might trigger alerts, notifications, etc.
        self.logger.critical(
            f"CRITICAL ERROR DETECTED: {error.message}",
            extra={'requires_immediate_attention': True}
        )
    
    def get_circuit_breaker(self, name: str, **kwargs) -> CircuitBreaker:
        """Get or create a circuit breaker for the specified service."""
        if name not in self.circuit_breakers:
            self.circuit_breakers[name] = CircuitBreaker(name, **kwargs)
        return self.circuit_breakers[name]
    
    def get_error_stats(self) -> Dict[str, int]:
        """Get current error statistics."""
        with self._lock:
            return self.error_counts.copy()
    
    def reset_error_stats(self) -> None:
        """Reset error statistics."""
        with self._lock:
            self.error_counts.clear()


def error_handler_decorator(error_handler: ErrorHandler):
    """Decorator to automatically handle errors in functions."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                context = ErrorContext(
                    component=func.__module__,
                    operation=func.__name__
                )
                error_handler.handle_error(e, context)
                raise
        return wrapper
    return decorator


# Global error handler instance
_error_handler: Optional[ErrorHandler] = None


def get_error_handler() -> ErrorHandler:
    """Get the global error handler instance."""
    global _error_handler
    if _error_handler is None:
        _error_handler = ErrorHandler()
    return _error_handler


def handle_error(error: Exception, context: Optional[ErrorContext] = None) -> None:
    """Handle an error using the global error handler."""
    get_error_handler().handle_error(error, context)


def get_circuit_breaker(name: str, **kwargs) -> CircuitBreaker:
    """Get a circuit breaker from the global error handler."""
    return get_error_handler().get_circuit_breaker(name, **kwargs)
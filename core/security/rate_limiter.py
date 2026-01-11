"""
Rate Limiting System for Camellia Shield

Provides protection against brute-force attacks, API abuse, and DoS attempts.
Implements sliding window rate limiting per user/IP with configurable policies.
"""

import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class RateLimitPolicy:
    """Rate limit policy configuration"""
    max_attempts: int
    window_seconds: int
    lock_duration_seconds: int = 0  # 0 = no lock, > 0 = lock duration


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded"""
    def __init__(self, identifier: str, retry_after: int):
        self.identifier = identifier
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded for {identifier}. Retry after {retry_after} seconds.")


class RateLimiter:
    """
    Thread-safe sliding window rate limiter.
    
    Features:
    - Per-identifier (IP, user, etc.) tracking
    - Sliding window algorithm (precise)
    - Automatic cleanup of old entries
    - Account locking support
    - Multiple policies for different  endpoints
    
    Example:
        limiter = RateLimiter()
        limiter.add_policy("login", RateLimitPolicy(5, 300))  # 5 attempts per 5 minutes
        
        if limiter.check_limit("login", "192.168.1.1"):
            # Allow request
        else:
            # Reject request
    """
    
    def __init__(self):
        self.attempts: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        self.locked_until: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.policies: Dict[str, RateLimitPolicy] = {}
        self.lock = Lock()
        
        # Default policies
        self._setup_default_policies()
    
    def _setup_default_policies(self):
        """Setup default rate limit policies"""
        self.add_policy(
            "login",
            RateLimitPolicy(
                max_attempts=5,
                window_seconds=300,  # 5 minutes
                lock_duration_seconds=900  # 15 minutes lock after 5 failures
            )
        )
        
        self.add_policy(
            "api",
            RateLimitPolicy(
                max_attempts=60,
                window_seconds=60  # 60 requests per minute
            )
        )
        
        self.add_policy(
            "file_operation",
            RateLimitPolicy(
                max_attempts=20,
                window_seconds=60  # 20 operations per minute
            )
        )
    
    def add_policy(self, policy_name: str, policy: RateLimitPolicy):
        """Add or update a rate limit policy"""
        with self.lock:
            self.policies[policy_name] = policy
    
    def check_limit(self, policy_name: str, identifier: str) -> Tuple[bool, Optional[int]]:
        """
        Check if identifier is within rate limit.
        
        Args:
            policy_name: Name of the policy to check against
            identifier: Unique identifier (IP address, user ID, etc.)
        
        Returns:
            (allowed, retry_after): Tuple of whether request is allowed and seconds until retry
        """
        if policy_name not in self.policies:
            # No policy defined, allow by default
            return True, None
        
        policy = self.policies[policy_name]
        now = time.time()
        
        with self.lock:
            # Check if account is locked
            if identifier in self.locked_until.get(policy_name, {}):
                locked_until = self.locked_until[policy_name][identifier]
                if now < locked_until:
                    retry_after = int(locked_until - now)
                    return False, retry_after
                else:
                    # Lock expired, remove it
                    del self.locked_until[policy_name][identifier]
            
            # Clean old attempts outside the window
            self.attempts[policy_name][identifier] = [
                timestamp for timestamp in self.attempts[policy_name][identifier]
                if now - timestamp < policy.window_seconds
            ]
            
            # Check attempt count
            attempt_count = len(self.attempts[policy_name][identifier])
            
            if attempt_count >= policy.max_attempts:
                # Rate limit exceeded
                oldest_attempt = min(self.attempts[policy_name][identifier])
                retry_after = int(policy.window_seconds - (now - oldest_attempt)) + 1
                
                # Apply lock if policy specifies
                if policy.lock_duration_seconds > 0:
                    self.locked_until[policy_name][identifier] = now + policy.lock_duration_seconds
                    retry_after = policy.lock_duration_seconds
                
                return False, retry_after
            
            # Record this attempt
            self.attempts[policy_name][identifier].append(now)
            
            return True, None
    
    def reset(self, policy_name: str, identifier: str):
        """
        Reset rate limit for an identifier (e.g., after successful login).
        
        Args:
            policy_name: Name of the policy
            identifier: Unique identifier to reset
        """
        with self.lock:
            if policy_name in self.attempts and identifier in self.attempts[policy_name]:
                del self.attempts[policy_name][identifier]
            
            if policy_name in self.locked_until and identifier in self.locked_until[policy_name]:
                del self.locked_until[policy_name][identifier]
    
    def get_remaining_attempts(self, policy_name: str, identifier: str) -> Optional[int]:
        """
        Get number of remaining attempts for an identifier.
        
        Args:
            policy_name: Name of the policy
            identifier: Unique identifier
        
        Returns:
            Number of remaining attempts, or None if no policy defined
        """
        if policy_name not in self.policies:
            return None
        
        policy = self.policies[policy_name]
        now = time.time()
        
        with self.lock:
            # Clean old attempts
            self.attempts[policy_name][identifier] = [
                timestamp for timestamp in self.attempts[policy_name][identifier]
                if now - timestamp < policy.window_seconds
            ]
            
            attempt_count = len(self.attempts[policy_name][identifier])
            return max(0, policy.max_attempts - attempt_count)
    
    def is_locked(self, policy_name: str, identifier: str) -> bool:
        """Check if an identifier is currently locked"""
        now = time.time()
        
        with self.lock:
            if policy_name in self.locked_until and identifier in self.locked_until[policy_name]:
                locked_until = self.locked_until[policy_name][identifier]
                if now < locked_until:
                    return True
                else:
                    # Lock expired
                    del self.locked_until[policy_name][identifier]
        
        return False
    
    def cleanup_old_entries(self):
        """
        Cleanup old entries to prevent memory bloat.
        Should be called periodically (e.g., every hour).
        """
        now = time.time()
        
        with self.lock:
            # Cleanup attempts
            for policy_name in list(self.attempts.keys()):
                if policy_name not in self.policies:
                    continue
                
                policy = self.policies[policy_name]
                
                for identifier in list(self.attempts[policy_name].keys()):
                    self.attempts[policy_name][identifier] = [
                        timestamp for timestamp in self.attempts[policy_name][identifier]
                        if now - timestamp < policy.window_seconds
                    ]
                    
                    # Remove empty lists
                    if not self.attempts[policy_name][identifier]:
                        del self.attempts[policy_name][identifier]
            
            # Cleanup locks
            for policy_name in list(self.locked_until.keys()):
                for identifier in list(self.locked_until[policy_name].keys()):
                    if now >= self.locked_until[policy_name][identifier]:
                        del self.locked_until[policy_name][identifier]


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def init_rate_limiter():
    """Initialize global rate limiter"""
    global _rate_limiter
    _rate_limiter = RateLimiter()


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance"""
    if _rate_limiter is None:
        raise RuntimeError("Rate limiter not initialized. Call init_rate_limiter() first.")
    return _rate_limiter

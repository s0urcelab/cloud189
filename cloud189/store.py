"""
Token storage implementations for the Cloud189 SDK
"""

from abc import ABC, abstractmethod

class Store(ABC):
    """Abstract base class for token storage"""
    
    @abstractmethod
    def get(self):
        """Get stored token data"""
        pass
    
    @abstractmethod
    def update(self, data):
        """Update stored token data"""
        pass

class MemoryStore(Store):
    """In-memory token storage implementation"""
    
    def __init__(self):
        self._data = None
    
    def get(self):
        return self._data
    
    def update(self, data):
        self._data = data 
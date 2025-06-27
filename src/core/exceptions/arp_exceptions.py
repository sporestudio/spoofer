#!/usr/bin/env python3

"""
ARP Exceptions Module
-----------------

This module defines custom exceptions for the ARP spoofing strategy.
These exceptions are used to handle errors specific to ARP spoofing operations.
"""

class ArpSpoofingError(Exception):
    """
    Base exception class for ARP spoofing errors.
    This class can be extended for more specific ARP spoofing exceptions.
    """
    _DEFAULT_ERROR_MESSAGE = "An error occurred during ARP spoofing."

    def __init__(self, message: str = _DEFAULT_ERROR_MESSAGE):
        super().__init__(message)
    
class ArpSpoofingLoopError(ArpSpoofingError):
    """
    Exception raised when an error occurs in the ARP spoofing loop.
    This could be due to network issues, invalid parameters, or other runtime errors.
    """
    _LOOP_ERROR_MESSAGE = "An error occurred in the ARP spoofing loop."

    def __init__(self, message: str = _LOOP_ERROR_MESSAGE):
        super().__init__(message)

class ArpSpoofingStartError(ArpSpoofingError):
    """
    Exception raised when the ARP spoofing attack fails to start.
    This could be due to invalid target or gateway IPs, or other initialization issues.
    """
    _START_ERROR_MESSAGE = "Failed to start ARP spoofing attack."

    def __init__(self, message: str = _START_ERROR_MESSAGE):
        super().__init__(message)

class ArpSpoofingStopError(ArpSpoofingError):
    """
    Exception raised when the ARP spoofing attack fails to stop.
    This could be due to issues in stopping the thread or cleaning up resources.
    """
    _STOP_ERROR_MESSAGE = "Failed to stop ARP spoofing attack."

    def __init__(self, message: str = _STOP_ERROR_MESSAGE):
        super().__init__(message)

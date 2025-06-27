#!/usr/bin/env python3

"""
DNS Exceptions Module
-----------------

This module defines custom exceptions for DNS-related operations.
These exceptions are used to handle errors specific to DNS spoofing or resolution issues.
"""

class DnsSpoofingError(Exception):
    """
    Base exception class for DNS spoofing errors.
    This class can be extended for more specific DNS spoofing exceptions.
    """
    _DEFAULT_ERROR_MESSAGE = "An error occurred during DNS spoofing."

    def __init__(self, message: str = _DEFAULT_ERROR_MESSAGE):
        super().__init__(message)

class DnsSpoofingLoopError(DnsSpoofingError):
    """
    Exception raised when an error occurs in the DNS spoofing loop.
    This could be due to network issues, invalid parameters, or other runtime errors.
    """
    _LOOP_ERROR_MESSAGE = "An error occurred in the DNS spoofing loop."

    def __init__(self, message: str = _LOOP_ERROR_MESSAGE):
        super().__init__(message)

class DnsSpoofingStartError(DnsSpoofingError):
    """
    Exception raised when the DNS spoofing attack fails to start.
    This could be due to invalid target or gateway IPs, or other initialization issues.
    """
    _START_ERROR_MESSAGE = "Failed to start DNS spoofing attack."

    def __init__(self, message: str = _START_ERROR_MESSAGE):
        super().__init__(message)

class DnsSpoofingStopError(DnsSpoofingError):
    """
    Exception raised when the DNS spoofing attack fails to stop.
    This could be due to issues in stopping the thread or cleaning up resources.
    """
    _STOP_ERROR_MESSAGE = "Failed to stop DNS spoofing attack."

    def __init__(self, message: str = _STOP_ERROR_MESSAGE):
        super().__init__(message)

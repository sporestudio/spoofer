#!/usr/bin/env python3

"""
Block Internet Exceptions Module
-----------------

This module defines custom exceptions for blocking internet access.
"""

class BlockInternetError(Exception):
    """
    Base exception class for blocking internet access errors.
    This class can be extended for more specific blocking exceptions.
    """
    _DEFAULT_ERROR_MESSAGE = "An error occurred while blocking internet access."

    def __init__(self, message: str = _DEFAULT_ERROR_MESSAGE):
        super().__init__(message)

class BlockInternetLoopError(BlockInternetError):
    """
    Exception raised when an error occurs in the internet blocking loop.
    This could be due to network issues, invalid parameters, or other runtime errors.
    """
    _LOOP_ERROR_MESSAGE = "An error occurred in the internet blocking loop."

    def __init__(self, message: str = _LOOP_ERROR_MESSAGE):
        super().__init__(message)

class BlockInternetStartError(BlockInternetError):
    """
    Exception raised when the internet blocking operation fails to start.
    This could be due to invalid parameters or other initialization issues.
    """
    _START_ERROR_MESSAGE = "Failed to start internet blocking operation."

    def __init__(self, message: str = _START_ERROR_MESSAGE):
        super().__init__(message)

class BlockInternetStopError(BlockInternetError):
    """
    Exception raised when the internet blocking operation fails to stop.
    This could be due to issues in stopping the thread or cleaning up resources.
    """
    _STOP_ERROR_MESSAGE = "Failed to stop internet blocking operation."

    def __init__(self, message: str = _STOP_ERROR_MESSAGE):
        super().__init__(message)
#!/usr/bin.env python3

"""
Strategy module
-----------------
This module defines the base class for all strategies in the application.
It provides a structure for implementing different strategies
and ensures that they adhere to a common interface.
"""

from abc import ABC, abstractmethod

class AttackStrategy(ABC):
    """
    Abstract base class for attack strategies.
    All attack strategies should inherit from this class and implement the `execute` method.
    """

    @abstractmethod
    def start(self) -> None:
        """
        Starts the attack strategy.
        This method should be implemented by subclasses to define the attack logic.
        """
        pass

    @abstractmethod
    def stop(self) -> None:
        """
        Stops the attack strategy.
        This method should be implemented by subclasses to define how to stop the attack.
        """
        pass

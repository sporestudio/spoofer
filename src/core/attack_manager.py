#!/usr/bin/env python3

"""
Attack Manager Module
-----------------

This module manages the execution of various network attacks.
It provides methods to start and stop attacks, and handles exceptions related to attack operations.
"""

from core.strategies.strategy import AttackStrategy

class AttackManager:
    """
    Class to manage network attacks.
    It provides methods to start and stop attacks, and handles exceptions related to attack operations.
    """

    def __init__(self):
        """
        Initializes the AttackManager with no active attack.
        """
        self.active_attack: AttackStrategy = None

    def set_strategy(self, strategy: AttackStrategy) -> None:
        """
        Sets the attack strategy to be used by the manager.

        :param strategy: An instance of a class that inherits from AttackStrategy.
        """
        if self.active_attack:
            self.active_attack.stop()
        self.active_attack = strategy

    def start(self) -> None:
        """
        Starts the currently set attack strategy.
        If no strategy is set, it raises an exception.
        """
        if not self.active_attack:
            raise ValueError("No attack strategy set.")
        self.active_attack.start()

    def stop(self) -> None:
        """
        Stops the currently active attack strategy.
        If no strategy is active, it raises an exception.
        """
        if self.active_attack:
            self.active_attack.stop()
            self.active_attack = None

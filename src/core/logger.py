#!/usr/bin/env python3

"""
Logger module
-----------------

This module provides a simple logging utility that can be used to log messages
at different levels (info, warning, error) to the console.
It can be extended to log to files or other outputs as needed.
"""

class Logger:
    def __init__(self, output_widget=None):
        """
        Initializes the Logger with an optional output widget.
        If an output widget is provided, log messages will be displayed in it.
        """
        self._output_widget = output_widget

    def log(self, message: str) -> None:
        """
        Logs a message at the info level.
        If an output widget is provided, the message will be displayed in it.
        """
        print(f"[INFO] {message}")
        if self._output_widget:
            self._output_widget.config(state='normal')
            self._output_widget.insert('end', message + '\n')
            self._output_widget.yview('end')
            self._output_widget.config(state='disabled')

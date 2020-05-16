"""This file will contain the function `pattern_create`
which will be used to generate a specific set of characters to send
after crashing the application to determine the offset value.

Name: pattern_create.py

Raises:
    PatternCreateError
"""


class PatternCreateError(Exception):
    """Will handle any errors throughout the pattern generation
    process.
    """
    def __init__(self, error_msg):
        super().__init__(error_msg)


def pattern_create(pattern_length):
    """This function will generate a specific pattern of characters
    to help find offset for buffer overflow.

    Args:
        pattern_length (int): The length of the pattern to generate

    Raises:
        PatternCreateError:
    """
    pattern = ""


    return pattern
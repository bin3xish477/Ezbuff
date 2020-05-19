"""This file will contain the function `pattern_create`
which will be used to generate a specific set of characters to send
after crashing the application to determine the offset value.

Name: pattern_create.py
"""

from sys import exit

class MaximumPatternLengthError(Exception):
    """Will handle any errors throughout the pattern generation
    process.
    """
    def __init__(self, error_msg):
        super().__init__(error_msg)


def pattern_create(length):
    """This function will generate a specific pattern of characters
    to help find offset for buffer overflow.

    Args:
        length (int): The length of the pattern to generate (dependent on the `num_of_bytes` variable)

    Raises:
        PatternCreateError:
    """
    try:
        if not length:
            raise TypeError("The `num_bytes_crash` variable must be set before sending a pattern payload!")
        if length > 20280:
            raise MaximumPatternLengthError("The length of the pattern cannot exceed 20280 characters")
    except TypeError as err:
        print(f"TypeError: {err}")
        exit(1)
    except MaximumPatternLengthError as err:
        print(f"MaximumPatternLengthError: {err}")
        exit(1)

    UPPERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    LOWERS = "abcdefghijklmnopqrstuvwxyz"
    DIGITS = "0123456789"
    pattern = ""

    for digit in DIGITS:
        for lower in LOWERS:
            for upper in UPPERS:
                if len(pattern) > length:
                    return pattern
                pattern += (digit+lower+upper)

"""This file will contain the function `pattern_create`
which will be used to generate a specific set of characters to send
after crashing the application to determine the offset value.

Name: pattern_create.py
"""


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
        if length > 20280:
            raise MaximumPatternLengthError("The length of the pattern cannot exceed 20280 characters")
    except MaximumPatternLengthError as err:
        print(f"MaximumPatternLengthError: {err}")

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

class BbotParsingError(Exception):
    """Exception raised for errors in the bbot module.
    Attributes:
        module -- module which caused the error
        message -- explanation of the error
    """

    def __init__(self, module, message):
        self.module = module
        self.message = message
        super().__init__(self.message)


class PartiallyDataError(Exception):
    "Raised when the input value is less than 18"
    pass

# -*- coding: utf-8 -*-
#
# All exceptions thrown by the threat_intel module
#


class InvalidRequestError(Exception):

    """Raised by MultiRequest when it can't figure out how to make a request."""
    pass


class MissingConfigError(Exception):

    """An error to throw when configuration is missing"""
    pass


class Cloud189Error(Exception):
    """Base class for exceptions in this module."""
    pass

class LoginError(Cloud189Error):
    """Exception raised for errors in the login process."""
    pass

class AdvReqError(Cloud189Error):
    """Exception raised for errors in the advreq process."""
    pass

class RsaKeyError(Cloud189Error):
    pass

class SessionKeyError(Cloud189Error):
    pass

class UploadError(Cloud189Error):
    """Exception raised for errors during file upload."""
    pass

class DeleteError(Cloud189Error):
    pass

class PlayUrlError(Cloud189Error):
    pass

class GetFilesError(Cloud189Error):
    pass

class GetUserInfoError(Cloud189Error):
    pass
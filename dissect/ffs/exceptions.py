class Error(Exception):
    pass


class NotADirectoryError(Error):
    pass


class FileNotFoundError(Error):
    pass


class NotASymlinkError(Error):
    pass

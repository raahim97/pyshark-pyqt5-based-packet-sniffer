import sys


class UnsupportedVersionException(Exception):
    pass


if sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 5):
    raise UnsupportedVersionException("Your version of Python is unsupported. "
                                      "Pyshark and pyqt5 requires Python >= 3.5 & Wireshark >= 2.2.0. "
                                      " Please upgrade your version!!!")

from pyshark.capture.live_capture import LiveCapture
from pyshark.capture.file_capture import FileCapture

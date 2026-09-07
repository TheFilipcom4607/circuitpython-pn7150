"""Desktop stand-in for CircuitPython's ``busio`` module.

Enough of an I2C to construct a PN7150; it answers no traffic, so only the
pure-logic paths are exercised on the host.
"""


class I2C:
    def __init__(self, scl=None, sda=None, frequency=100000):
        self.scl, self.sda, self.frequency = scl, sda, frequency
        self._locked = False

    def try_lock(self):
        if self._locked:
            return False
        self._locked = True
        return True

    def unlock(self):
        self._locked = False

    def readfrom_into(self, address, buf, start=0, end=None):
        raise OSError("no device on the stub bus")

    def writeto(self, address, buf):
        raise OSError("no device on the stub bus")

    def deinit(self):
        pass

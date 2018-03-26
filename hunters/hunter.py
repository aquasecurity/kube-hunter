from abc import ABCMeta, abstractmethod


class Hunter(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def hunt(self, *args, **kwargs):
        pass

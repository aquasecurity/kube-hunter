class HunterBase:
    publishedVulnerabilities = 0

    @staticmethod
    def parse_docs(docs):
        """returns tuple of (name, docs)"""
        if not docs:
            return __name__, "<no documentation>"
        docs = docs.strip().split("\n")
        for i, line in enumerate(docs):
            docs[i] = line.strip()
        return docs[0], " ".join(docs[1:]) if len(docs[1:]) else "<no documentation>"

    @classmethod
    def get_name(cls):
        name, _ = cls.parse_docs(cls.__doc__)
        return name

    def publish_event(self, event):
        # Import here to avoid circular import from events package.
        # imports are cached in python so this should not affect runtime
        from ..events.event_handler import handler  # noqa

        handler.publish_event(event, caller=self)


class ActiveHunter(HunterBase):
    pass


class Hunter(HunterBase):
    pass


class Discovery(HunterBase):
    pass

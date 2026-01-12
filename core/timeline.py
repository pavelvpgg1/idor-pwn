import time

class Timeline:
    def __init__(self):
        self.events = []
        self.start = time.time()

    def add(self, message: str):
        self.events.append({
            "time": round(time.time() - self.start, 2),
            "event": message
        })

    def dump(self):
        return self.events

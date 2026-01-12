class Bruteforcer:
    def __init__(self, start, end):
        self.start = start
        self.end = end

    def ids(self):
        for i in range(self.start, self.end + 1):
            yield i

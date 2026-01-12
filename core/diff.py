class DiffEngine:
    def diff(self, own: dict, foreign: dict):
        diff = {}

        for key in foreign:
            own_val = own.get(key)
            foreign_val = foreign.get(key)

            if own_val != foreign_val:
                diff[key] = {
                    "own": own_val,
                    "foreign": foreign_val
                }

        return diff

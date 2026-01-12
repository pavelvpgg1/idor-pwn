class Validator:
    def __init__(self, ownership_field, current_user_id):
        self.ownership_field = ownership_field
        self.current_user_id = current_user_id

    def is_idor(self, response_json):
        owner = response_json.get(self.ownership_field)
        return owner is not None and owner != self.current_user_id

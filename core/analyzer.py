class Analyzer:
    def __init__(self, endpoint_template):
        self.endpoint_template = endpoint_template

    def build_path(self, obj_id):
        return self.endpoint_template.replace("{id}", str(obj_id))

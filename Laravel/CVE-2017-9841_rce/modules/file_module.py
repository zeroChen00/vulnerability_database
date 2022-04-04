

class file_moduler:
    def __init__(self) -> None:
        self.type_for_save = 'a'


    def save_value_file(self, value, file):
        with open(file, self.type_for_save) as f:
            f.write(value)
            f.close()
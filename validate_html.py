import sys
import os
import glob
from html.parser import HTMLParser

class MyHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.errors = []

    def handle_starttag(self, tag, attrs):
        pass

    def handle_endtag(self, tag):
        pass

    def handle_data(self, data):
        pass

    def error(self, message):
        self.errors.append(message)

def validate_html(file_path):
    parser = MyHTMLParser()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        parser.feed(content)
        if parser.errors:
            return parser.errors
        else:
            return None
    except Exception as e:
        return [str(e)]

if __name__ == "__main__":
    if len(sys.argv) > 1:
        patterns = sys.argv[1:]
        files = []
        for pattern in patterns:
            files.extend(glob.glob(pattern))
    else:
        files = glob.glob('templates/*.html')

    all_errors = {}
    for file in files:
        if os.path.isfile(file):
            errors = validate_html(file)
            if errors:
                all_errors[file] = errors
        else:
            print(f"File not found: {file}")

    if all_errors:
        for file, errs in all_errors.items():
            print(f"Errors in {file}:")
            for err in errs:
                print(f"  {err}")
    else:
        print("No HTML errors found in the provided files.")

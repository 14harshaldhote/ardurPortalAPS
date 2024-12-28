import os

# Define the base directory for templates inside the aps folder
base_dir = "aps/templates"

# Directory structure to be created
directories = [
    base_dir,  # main templates folder
    os.path.join(base_dir, "dashboard"),  # dashboard folder
    os.path.join(base_dir, "card"),  # card folder
    os.path.join(base_dir, "basic"),  # basic folder
]

# Create directories
for directory in directories:
    os.makedirs(directory, exist_ok=True)

# Create base.html file inside templates
base_html_path = os.path.join(base_dir, "base.html")
with open(base_html_path, "w") as file:
    file.write("<!DOCTYPE html>\n<html>\n<head>\n    <title>Base Template</title>\n</head>\n<body>\n    {% block content %}{% endblock %}\n</body>\n</html>")

print(f"Directory structure and {base_html_path} file created successfully!")

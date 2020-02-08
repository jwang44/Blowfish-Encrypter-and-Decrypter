# -*- coding: utf-8 -*-
from tkinter import *
from Crypto.Cipher import Blowfish
import base64
class blowfish():
    def __init__(self,key):
        self.key = key.encode('utf-8')
        if len(self.key)>=8:
            self.iv = self.key[0:8]
        else:
            self.iv = self.key + ('\0' * (8 - len(self.key)))
        self.mode = Blowfish.MODE_CBC

    def set_key(self,new_key):
        self.key = new_key.encode('utf-8')
        if len(self.key) >= 8:
            self.key = self.key[0:8]
        else:
            self.key = self.key + ('\0' * (8 - len(self.key)))

    def encrypt(self,code):  # 加密
        l = len(code)
        n = 8
        if l % 8 != 0 :
            code = code + '\0' * (8 - (l %8))
        code = code.encode('utf-8')
        cryptor = Blowfish.new(self.key,self.mode,self.iv)
        encode = cryptor.encrypt(code)
        return base64.encodebytes(encode)

    def decode(self,encode):  # 解密
        cryptor = Blowfish.new(self.key, self.mode, self.iv)
        code = cryptor.decrypt(base64.decodebytes(encode))
        return (code.decode('utf-8')).rstrip('\0')


def display():
    root = Tk()  # 新建窗口
    root.resizable(0, 0)  # 尺寸不可修改
    root.title('Blowfish')  # 窗口标题
    plain_txt = Text(root, width=16, height=5, font="Helvetica 40", bg='#E0FFFF', bd=10)  # 明文文本框
    plain_txt.grid(row=0, column=0)
    label_plain = Label(root, text='明文')  # 明文提示标
    label_plain.grid(row=1, column=0)
    encrypt_img = PhotoImage(file='encrypt.png')  # 按钮贴图
    decrypt_img = PhotoImage(file='decrypt.png')
    def encrypt():  # 加密函数
        # key = input("请输入密钥:")
        key = var.get()
        r = blowfish(key)
        plain = plain_txt.get('0.0', 'end')  # 获取明文
        secret = r.encrypt(plain)  # 加密
        secret_txt.insert(INSERT, secret)  # 显示密文

        #b = r.decode(secret)
        #print(b)

    def decrypt():
        key = var.get()  # 从密钥输入框获取密钥值
        # key = input("请 输入密钥:")
        r = blowfish(key)
        # secret = (Byte*) secret_txt.get('0.0', 'end')
        secret = bytes(secret_txt.get('0.0', 'end'), 'utf-8')  # 编码格式转换
        plain = r.decode(secret)  # 解密
        plain_txt.insert(INSERT, plain)  # 显示明文

    btn_encrypt = Button(root, width=50, height=50, image=encrypt_img, command=encrypt)  # 加密按钮
    btn_encrypt.grid(row=2, column=0)
    btn_decrypt = Button(root, width=50, height=50, image=decrypt_img, command=decrypt)  # 解密按钮
    btn_decrypt.grid(row=2, column=2)
    secret_txt = Text(root, width=16, height=5, font="Helvetica 40", bg='#E6E6FA', bd=10)  #密文文本框
    secret_txt.grid(row=0, column=2)
    label_secret = Label(root, text='密文')  # 密文提示标
    label_secret.grid(row=1, column=2)
    var = StringVar()
    key_entry = Entry(root, textvariable=var)  # 密钥输入框
    var.set("Enter key here:")
    key_entry.grid(row=3, column=0, columnspan=4)
    mainloop()

if __name__ == "__main__":
    display()

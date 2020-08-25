---
title: "HackTheBox — SwagShop Writeup"
date: 2020-08-25 22:42:00 +/-0800
categories: [HackTheBox,Linux Machines]
tags: [Magento, vi, sudo, php, wfuzz, Froghopper attack, Swagshop]
image: /assets/img/Posts/SwagShop.png
---

> SwagShop from HackTheBox is an retired machine which had a web service running with an outdated vulnerable Magento CMS that allows us to perform an RCE and get a reverse shell. Later we can exploit sudo privileges to run vi as root through sudo command and exploit it to get root shell.

## Enumeration
Lets start out with Nmap scan to find out open ports and services:

![Nmap Scan](/assets/img/Posts/Swagshop/nmap.png)

We got open port `22 & 80` and **HTTP** service running on port 80.

## Web Service Enumeration

![Magento HomeScreen](/assets/img/Posts/Swagshop/magento.png)

The web application is running on **Magento CMS** and on the bottom of the page we observe that it’s running on 2014 version so lets try searching for exploits and in background run wfuzz to find out directories associated with this application

![wfuzz](/assets/img/Posts/Swagshop/wfuzz.png)

Lets run Searchsploit to look for publicly available exploits and we found out a exploit `Magento eCommerce- Remote code Execution-37977.py` which creates a admin account credentials which can be used to login to admin panel on <http://swagshop.htb/index.php/admin/>

![searchsploit](/assets/img/Posts/Swagshop/searchsploit.png)

## Creating an Admin User

The Magento eCommerce- Remote code Execution exploit creates a new admin account with `forme/forme` as credentials. I just modified the target and the credentials as `cfx/cfx` and launched it to get an admin account

![exploit](/assets/img/Posts/Swagshop/exploit.png)

![exploit1](/assets/img/Posts/Swagshop/exploit1.png)

Now we can login to the admin panel on <http://swagshop.htb/index.php/admin/> using the credentials `cfx:cfx`

![login](/assets/img/Posts/Swagshop/login.png)

![login1](/assets/img/Posts/Swagshop/login1.png)

## Froghopper Attack - Magento RCE

Initially when I did this box I used Magento connect manager to add an file system extension through you could add or edit PHP files to get an reverse shell but now that vector has been removed and the only method which we can use is called **Froghopper attack**

Using this [**article**](https://www.foregenix.com/blog/anatomy-of-a-magento-attack-froghopper) I was able to use this attack, We start by allowing the symlinks option in template settings:

![frog1](/assets/img/Posts/Swagshop/frog1.png)

![frog2](/assets/img/Posts/Swagshop/frog2.png)

![frog3](/assets/img/Posts/Swagshop/frog3.png)

Now since we have to upload a png file as a category thumbnail so we take a png file and echo a reverse shell in it:

![revshell](/assets/img/Posts/Swagshop/revshell.png)

Uploading the png file to Catalog > Manage categories:

![upload](/assets/img/Posts/Swagshop/upload.png)

As we can check if our image file has been uploaded successfully by visiting <http://swagshop.htb/media/catalog/category/shell.php.png>

![upload1](/assets/img/Posts/Swagshop/upload1.png)

Now we have to create a newsletter template and inject the payload mentioned in the article: `{{block type=’core/template’ template=’../../../../../../media/catalog/category/shell.php.png’}}`

![template](/assets/img/Posts/Swagshop/template.png)

![template1](/assets/img/Posts/Swagshop/template1.png)

We just have to save the template and later preview template to spawn our reverse shell.

## Shell as www-data

Lets start the listener on port 4444 and then click on preview template button.

![shell](/assets/img/Posts/Swagshop/shell.png)

We see the user flag in the home directory of user haris.

## Privilege Escalation

The user www-data has sudo privileges to execute binary `vi` as root. We can spawn a shell from within vi using `:!/bin/sh` and it’ll spawn root shell.

![privesc1](/assets/img/Posts/Swagshop/privesc1.png)

![privesc2](/assets/img/Posts/Swagshop/privesc2.png)


Thanks for reading <3

---
title: brixelCTF - Some challenges 
category: writeup
tags: others
---
Writeups for the challenges I solved or was working on with my teamates.

# Reversing-Cracking

## Cookieee!

> This stupid cookie clicker game...
Legend has it there is a reward when you reach 10000000 or more clicks
Can you think of a way to get that many clicks?

This was a very fun and interesting challenge where we use the cheat engine available for download [here](https://cheatengine.org/).

I personally solved this challenge on my windows VM so I downloaded the windows exe for the cheat engine and the challenge binary.

Unzipping and running the binary presents us with a cookie clicker game which increases our score by one every time we click on a cookie.

![cookiee](/assets/img/brixelCTF/cookie1.png)

At first I was chasing down the wrong path of trying to attach the process with gdb on linux and IDA on windows and staring at the disassembly hoping to change the value of a register which would give me the required score. However, after talking to people on the discord it was not that at all, instead it was just using a cheat engine which made this very easy.

Running cheat engine and attaching the process we can then search for values in memory and watch them change in realtime.

We can enter our values in the value field at the main screen.

First we search for 0's as our initial score is 0. After that click on a cookie and do a `Next scan` for the value 1 and then the same for value 2. This filters out the addresses that have the value 0 → value 1 → value 2 instead of just looking for all the addresses with the value 0,1 or 2.

![cookiee](/assets/img/brixelCTF/cookieee2.png)

There are 2 addresses which have been changing and changing the values at both addresses to 1000000 gives us the flag.

![cookiee](/assets/img/brixelCTF/cookieee3.png)

Resources:

- [https://github.com/imadr/Unity-game-hacking](https://github.com/imadr/Unity-game-hacking)
- [https://www.youtube.com/playlist?list=PLNffuWEygffbue0tvx7IusDmfAthqmgS7](https://www.youtube.com/playlist?list=PLNffuWEygffbue0tvx7IusDmfAthqmgS7)

## noPEEKing

> Hidden inside this exe file is a flag
Up to you to find it

The challenges name noPEEKing gives us a hint that it might be a dotnet binary which can be decompiled using dotPeek, dnSpy or ilSpy.

Personally I used dnSpy.

Decompiling the binary and taking a look at the source code gives us the flag.

![cookiee](/assets/img/brixelCTF/nopeeking1.png)

## registerme.exe

> This program needs to be activated
Can you figure out how to do it?

I personally used IDA for this challenge for debugging.

After opening the binary up in IDA, it prompts us to find a dll file to which I just clicked cancel.

Looking through the disassembly we can find a `activation.key` string which is first being duplicated and the being passed into `_vbaStrCmp` along with the duplicated variable after which there is a conditional jump takes place if the value returned by the function is 0. This value will be 0 as the string is being duplicated and then compared. We can bypass this check by simply patching the binary and replacing the `jz` instruction to `jnz` instruction which is the jump if not zero. This would mean that our program won't jump to the section where it says Not Registered but instead continue to the registered section.

![cookiee](/assets/img/brixelCTF/registerme1.png)

Hitting continue and removing the break point we can retrieve the flag.

![cookiee](/assets/img/brixelCTF/registerme2.png)

Resources:

I used the following video to understand debugging with IDA.

- [https://youtu.be/tt15P5Om3Zg](https://youtu.be/tt15P5Om3Zg)

## android-app

> This little android app requires a password, can you find it?
the flag is the password

We have an `apk` file which is used by android to install apps.

We can use `apktool` with the `decode` option to check what the app does.

```c
apktool d brixelCTF.apk
```

We now have a brixelCTF folder with a bunch of directories. Inside the `brixelCTF/smali/appinventor/ai_kevin_erna/brixelCTF` we can find Screen1, Screen2 and Screen3 smali files.

Taking a look at the source for the Screen1 file which we can presume is the login screen as found by running the apk file (I did it on a old phone I had lying around, probably a better idea to set up an environment to do that). 

I used smali2java to convert the code to java but was not necessary as just going over the code in Screen1.smali or [Screen1.java](http://screen1.java) file we can find the flag.

```java
const-string v2, "brixelCTF{th3_4ndr0ids_y0u_4r3_l00k1ng_f0r}"
```

# Internet

## login1

> My buddy is trying to become a web developer, he made this little login page. Can you get the password?
[http://timesink.be/login1/index.html](http://timesink.be/login1/index.html)

Just checking the source reveals the flag.

```jsx
function verify() {
		password = document.getElementById("the_password").value;
		if(password == "brixelCTF{w0rst_j4v4scr1pt_3v3r!}")
		{
			alert("Password Verified");
		}
		else 
		{
		alert("Incorrect password");
		}
	}
```

## login2

> Cool, you found the first password! He secured it more, could you try again?
[http://timesink.be/login2/index.html](http://timesink.be/login2/index.html)

Checking the source again reveals the flag.

```jsx
function verify() {
		password = document.getElementById("the_password").value;
		split = 6;
		if (password.substring(0, split) == 'brixel') 
		{
			if (password.substring(split*6, split*7) == '180790') 
			{
				if (password.substring(split, split*2) == 'CTF{st') 
				{
					if (password.substring(split*4, split*5) == '5cr1pt') 
					{
						if (password.substring(split*3, split*4) == 'd_j4v4') 
						{
							if (password.substring(split*5, split*6) == '_h3r3.') 
							{
								if (password.substring(split*2, split*3) == '1ll_b4') 
								{
									if (password.substring(split*7, split*8) == '54270}') 
									{
										alert("Password Verified")
									}
								}
							}
						}
					}
				}
			}
		}
		else 
		{
		alert("Incorrect password");
		}
	}
```

## login3

> Nice! you found another one! He changed it up a bit again, could you try again?
[http://timesink.be/login3/index.html](http://timesink.be/login3/index.html)

Checking the source shows that the javascript calls a function which is compared with the password.  Just calling the function from the console gives us the flag

```jsx
readTextFile("password.txt")
"brixelCTF{n0t_3v3n_cl05e_t0_s3cur3!}"
```

## login4

> Whow, another one! You're good! So I told my buddy how you managed to get the password last time, and he fixed it. Could you check again please?
[http://timesink.be/login4/index.html](http://timesink.be/login4/index.html)

This time the readTextFile function is being base64 decoded to get the contents.

Similar to one before just putting that in the console gives us the flag.

```jsx
atob(readTextFile("password.txt"))
"brixelCTF{even_base64_wont_make_you_secure}"
```

## login5

> Ok, THIS time it should be fine! if you find this one he is going to quit trying.
[http://timesink.be/login5/index.html](http://timesink.be/login5/index.html)

This time we get some obfuscated javascript which can be deobfuscated.

Removing the if statement at the end and just logging the output of newpassword and password we get the flag.

```jsx
function verify() {
  /** @type {function(number, ?): ?} */
  var __ = _0x58ab;
  password = document[__(404)](__(402))["value"];
  alphabet = __(403);
  newpassword = alphabet[__(408)](1, 1);
  newpassword = newpassword + alphabet[__(408)](17, 1);
  newpassword = newpassword + alphabet[__(408)](8, 1);
  newpassword = newpassword + alphabet["substr"](23, 1);
  newpassword = newpassword + alphabet[__(408)](4, 1);
  newpassword = newpassword + alphabet[__(408)](11, 1);
  newpassword = newpassword + alphabet[__(408)](2, 1);
  newpassword = newpassword + alphabet[__(408)](19, 1);
  newpassword = newpassword + alphabet[__(408)](5, 1);
  newpassword = newpassword + alphabet[__(408)](alphabet[__(407)] - 2, 1);
  newpassword = newpassword + alphabet["substr"](alphabet[__(407)] - 4, 1);
  newpassword = newpassword + alphabet[__(408)](1, 1);
  newpassword = newpassword + alphabet[__(408)](5, 1);
  newpassword = newpassword + alphabet["substr"](20, 1);
  newpassword = newpassword + alphabet[__(408)](18, 1);
  newpassword = newpassword + alphabet[__(408)](2, 1);
  newpassword = newpassword + alphabet["substr"](0, 1);
  newpassword = newpassword + alphabet[__(408)](19, 1);
  newpassword = newpassword + alphabet[__(408)](8, 1);
  newpassword = newpassword + alphabet[__(408)](alphabet[__(407)] - 4, 1);
  newpassword = newpassword + alphabet[__(408)](13, 1);
  newpassword = newpassword + alphabet["substr"](alphabet[__(407)] - 1, 1);
    console.log(newpassword);
  console.log(password);
}
verify()
"brixelctf{0bfuscati0n}"
```

## Browser check

> I found this weird website, but it will only allow 'ask jeeves crawler' to enter?
Can you get me in?

Checking the link gives the following message:

```jsx
Access denied! Ask Jeeves crawler allowed only!
```

Changing our user agent to Ask Jeeves Crawler's gives us the flag.

```
GET /browsercheck/ HTTP/1.1
Host: timesink.be
User-Agent: Mozilla/2.0 (compatible; Ask Jeeves/Teoma; +http://sp.ask.com/docs/about/tech_crawling.html)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```

```
congratulations
the flag is 'brixelCTF{askwho?}'
```

## Pathfinders #1

> These f*cking religious sects!
These guys brainwashed my niece into their demeted world of i-readings and other such nonsense.
The feds recently closed their churches, but it seems they are preparing for a new online platform to continue their malicious activities.
can you gain access to their admin panel to shut them down?
Their website is: [http://timesink.be/pathfinder/](http://timesink.be/pathfinder/)

After visiting the page we can see that there is a file include for home.php which includes the pages in the url and executes them. 

Checking the links on the page we see that there is a admin/index.php endpoint which requires http authentication usually stored in the .htpasswd file.

Using the page parameter to access admin/.htpasswd gives us the flag.

```
view-source:http://timesink.be/pathfinder/index.php?page=admin/.htpasswd
#normally you would brute force this, but that is not in scope of this challenge. The flag is: brixelCTF{unsafe_include} <br>
admin:$apr1$941ydmlw$aPUW.gCFcvUbIcP0ptVQF0
```

## Pathfinders #2

> It seems they updated their security. can you get the password for their admin section on their new site?
[http://timesink.be/pathfinder2/](http://timesink.be/pathfinder2/)
oh yeah, let's assume they are running a php version below 5.3.4 here...

Older versions of PHP were vulnerable to [this](https://defendtheweb.net/article/common-php-attacks-poison-null-byte) attack where we can append a %00 at the end of a string and php will only include the stuff before the null byte as everything after will be ignored.

Just visiting [http://timesink.be/pathfinder2/index.php?page=admin/.htpasswd.php](http://timesink.be/pathfinder2/index.php?page=admin/.htpasswd%00.php) gives us the flag.

```
Great work! the flag is brixelCTF{outdated_php}
```

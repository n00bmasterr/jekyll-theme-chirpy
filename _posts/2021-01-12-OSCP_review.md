---
title: OSCP Review 
category: writeup
tags: oscp
---

I did it! After a year of learning and working hard towards the certification coming from no IT work experience background. Admittedly I failed my first attempt with being just short and getting only 65 points. However, I managed to pass the second attempt with 80 points.

There were a lot of lesson's that I learned through this process of getting my certification which I have listed at the end.

# Attempt 1

I did my first attempt back in August which I failed with 65 points in hand.

The exam was scheduled to start at 10 am but because of problems with my webcam not focusing in on my ID I had to scan it and send it to them which consumed the first 15 minutes which already had me panicking. No sweat, there is still plenty of time left.

At around 10:15 - 10:20 I connected to my VPN and started attacking the machines. Like everyone advises I went straight for the buffer overflow 25 pointer. Half way through the exploitation process I realised I had my `autorecon` command typed into the terminal but I forgot to press enter🤦🏾‍♂️ (first mistake). The buffer overflow took me around an hour and I was 25 points down.

Next I decided to go for the 10 pointer machine which was very straight forward and took me around 30 minutes. After which I took a small 20 minute break. Coming back to my terminal I thought hey this is great I have almost half the points and its only been 2.5 hours. 

Then came the bad part where I had 2 20 point machines and 1 25 pointer to go but I was confused as to which one to attack first. At this point I made my second mistake where I just started jumping between machines and found myself getting confused between the services and ports on these 3 machines. But then I decided to stop hopping around and focus on one machine although the damage had been done as I had already spent 4 hours jumping around and had wasted the crucial time where I could have been enumerating the machines properly. No sweat though as after focusing on one machine I got a shell on the first 20 pointer in 45 minutes and then root in another 1.5 hours. At this point I was very happy and went for a shower to relax as I knew I had 55 points and I still had a lot of time to go.

I came back and started working on the second 20 pointer and the 25 pointer. I found myself making the same mistake again which jumping too much between these 2 machines. My first plan was to go for the 25 pointer so if I get root on that machine I will go to 80 points and can chill after. The 25 pointer was hard and I couldn't even get a initial foothold on the machine even after trying for hours. I left it alone for the time being and started focusing on the second 20 pointer. The initial foothold wasn't too hard and took just under an hour. 

This is where it all starts to go south as I took another short break and then came back to the PC hoping to finish up but unfortunately I could not find the `privesc` nor was I able to get a foot hold on the 25 pointer. I spent the rest of the time attempting to find something but just couldn't do it and stayed up all night doing the same thing over and over again expecting a different result.

The biggest mistake I made was staying up for 24+ hours, only eating around 100 grams of pasta salad and downing 2 big cans of energy drink (I don't drink much energy drinks and this was 7 months after I had it the last time).  At the end I had 65 points and was very disappointed in myself that I did not do the Lab report and missed out on the pass. After that I just played a game of PUBG (which I won luckily 😂) and just went to bed.

# Attempt 2

Much different to the last attempt this time I went in with a lot more confidence and after a big 4 month gap. During this gap I was busy with University assignments and playing some Capture the Flag games here and there. 

The exam started at 9 am and as soon as I got the lab connection I started scanning the machines in the background as I started working on buffer overflow. It took me around 1 hour to get the buffer overflow. 

After getting the buffer overflow I started working on the first 20 point machine and after getting nowhere I decided to work on the 10 point machine and got it within 1 hour and had around 35 points at 1 PM. 

I decided to go back to the 20 pointer and got a user shell in the next 30 minutes.

After this point I had a bit of a dry streak and did not get anywhere for the next couple of hours but I kept trying harder and forgot to try simpler which led me down a rabbit hole. I decided to leave the root part of the 20 pointer alone for the time and went for a break. After coming back I still wasn't quite seeing where to go so I decided to hop on the 25 pointer machine and saw a couple of things that I could do. However, I was still unsuccessful and thought about taking another break and go out for a walk.

While I was out on a walk I had a few new ideas which I immediately tried when I got home, one of which worked and I had a user shell on the 25 point machine. This was really helpful as this gave me a confidence boost and then went on to root the 25 point machine in the next 30-35 minutes. 

I was really happy at this point as I now had 25+25+10+10 for user on 20 pointer (Offsec has not confirmed the point levels for user shells iirc). But I did not want to stay on that 70 point mark and wanted a hard confirmation of getting enough points to pass. So, I tried to go for root on that machine and got it within an hour. 

At this stage I was only 12 hours in the exam and was pretty happy with myself. I decided to take a small nap and then go back to the machines and get all the necessary screenshots incase I missed any of them. 

I confirmed the control panel and the screenshots for the right flags almost 15 times as I didn't want to have that be a reason I failed. 

I attempted the last 20 point machine but was really tired and couldn't focus so I just ended the exam after confirming all of the exploits and steps that I had taken.

![https://media1.tenor.com/images/b620b1915fa4d87e81fe0d4c14a300d2/tenor.gif?itemid=15192446](https://media1.tenor.com/images/b620b1915fa4d87e81fe0d4c14a300d2/tenor.gif?itemid=15192446)

# Conclusion

Overall, the exam was really fun and exciting with some really important lessons that I learnt from my first attempt and the second attempt.

I am really happy to have passed the OSCP and hope to look for work now that its out of the way.

# Lessons Learned

- Try harder but also Try Simpler as that can save you a ton of time.
- Take many breaks during the exam and go out for a walk as this might help you get some ideas.
- Try to stay calm which is easier said than done. But this can have a big impact on the way that you think.
- Make sure to take good notes as you go so you wouldn't have to worry while writing the report.
- I personally found playing King of the hill/Hacking Battlegrounds like games quite beneficial as they put you in a time restricted environment forcing you to think faster and do things faster
- Believe in yourself and the work you have put in.

If you are reading this before your attempt. Good luck for your attempt and I hope you pass.

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*M7AaSdqX45djvM55M30HDQ.jpeg)

Hello dudes,  
I hope to find you well.

I started learn Windows Forensics a few month ago and this is my first time to get my hands dirty with a real image made by **Dr. Ali Hadi** @binaryz0ne.

Here all you wanna know about the case and related files  
https://github.com/ashemery/WindowsDFIR

**So, lets start….**

**First Question**: What is the hash value for the given forensic image?

Here you can variety tools (HashMyFiles, QuickHash or build-in Get-FileHash in powershell) but I used FTK imager.

After load the image:  
1- Select image and right click  
2- choose **Verify Drive/Image**

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*D13fR0868CcT33VXwa9r9A.png)

All hashes for image

Here we go, the answer is: **634ed59c1cf60ef0a7f62e06529b2b2d**

**Second Question**: Which user account was used to access some confidential documents and explain in detail what proof do you have to support your answer?

After mount the image you will find file called “ **Condidential.rtf** ” in **Joker profile** but we need more prove so, when you open any file/app it create a file automatically in **AutomaticDestinations-MS (it’s a type of jumplist)** you can find about it here [Link](https://forensafe.com/blogs/jumplist.html).

And user here we supposed he accessed to a file that he is unauthorized to access so, he opened it and left a **jumplist** artifact.

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*9PUpPIov2jeVDm_VLjjmoQ.png)

Data with Jumplist Explorer

Also, there is LNK artifact, created first time when you open file and hold a wealthy information. You can find about it here [Link](https://belkasoft.com/forensic-analysis-of-lnk-files).

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*yZvPHf6UyWdp6WOqeFcsIA.png)

Data with LEcmd

Here we go, the answer is: user is **Joker** and see upper to know our proof.

**Third Question**: Did the user access the confidential files from a local drive or network location and what proof do you have to support your answer?

If we saw previous screenshoot you can recognize that we have a 5 files 4 on shared network and one only locally.

If you click to see details of this file you can see these data so, if you click on **Entry #:002** you can find its details and from its path you can recognize it on shared network.

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*I_r2r2zIWaltEunlvd8fUQ.png)

Shared file Condidential.rtf

Also, you can recognize there is a file locally with same name. Here you can make sure he took a copy to his local machine and opened it.

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*HL87hglHeLPtXmpUyabcMw.png)

Local file Condidential.rtf

Here we go, the answer is: file opend from **local and** **network location** and see upper to know our proof.

**Fourth Question**: List all the files that were accessed with full paths.

We can use same **jumplist explorer** to figure out all paths

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*ULukfI0g_HCCC7hbobIufA.png)

All files that were accessed

Here we go, answers are:

**C:\\Users\\Joker\\Confidential.rtf  
\\\\192.168.70.128\\SHAREDJJ\\docs\\Confidential.rtf  
\\\\192.168.70.128\\SHAREDJJ\\docs\\Confidential\_02.docs  
\\\\192.168.70.128\\SHAREDJJ\\docs\\Confidential\_03.docs  
\\\\192.168.70.128\\SHAREDJJ\\docs\\Confidential\_04.docs**

**Fifth Question**: Provide two different evidence to prove that those files were truly accessed.

All what we did previously are evidences that “ **Joker** ” accessed these files truly (**Through Jumplist**) but Dr. Ali offered another option “ **LNK** ” files but **I searched a lot for them in Recent folder and other places and I didn’t find them.** But I found them finally **KEEP IN MIND TO USE CMD** to navigate folders because they may not appear in fornt of you.

Here we go, answers are: **Jumplist and LNK in details mentioned above.**

**Sixth Question:** Which application was used to open any of the confidential document(s)?

Here we can think to invistigate 2 places **“UserAssist”** and **“Prefetch File”**

**\*UserAssist =** keeps all apps launched recently and hold a wealthy info about them.

**\*Prefetch File =** file created first time when launch app and then help app to run faster and also hold a wealthy info about app.

So, from 2 places we can figure out what program used to open these files.

First place

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*Zzaczgu6Ofoz9gY8Zl7CqQ.png)

UserAssist

Second place

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*1xRiaAnQiLGf9V4kH6ganA.png)

Prefetch File

Here we go, the answer is: **WORDPAD.EXE**

## Get Ali Alaa’s stories in your inbox

Join Medium for free to get updates from this writer.

**\*\*Note: next 3 questions related to photo file see the README file.**

**Seventh Question:** What is the full path to the files of interest?

After mount the image file I can navigate to user profile and here what I found

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*DNToWluoQxBmzKBwU3d8aw.png)

Joker profile

So, here I found the **“haha.png”** filehe informed about it.

Here we go, the answer is: **\\Users\\Joker\\haha.png**

**Eighth Question:** What is the Volume Serial Number where the file exists?

Here I used **“VOL”** command using cmd

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*77ZOlUYZf6KWVry0L3S0Bw.png)

Volume Serial Number

Here we go, the answer is: **68D6–28DB**

**Ninth Question:** What are the Modified, Accessed, and Creation (MAC) timestamps in UTC for the file?

Here I used **FTK Imager** to access image file and I select **haha.png** photo and here MAC details

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*s3V3VdwKXSXq4ziYPrHqJQ.png)

MAC

Here we go, answers are:  
**2/15/2019, 5:00:21 AM  
2/15/2019, 5:00:22 AM  
2/15/2019, 5:00:21 AM**

**\*\*Note: next 4 questions related to DCode.exe but it’s tricky see the README file.**

**Tenth** **Questions**: Which user do you think ran the application and what evidence do you have to support your hypothesis?

As we learned previously any program launched will store in many places like “ **UserAssist** ” so, we must investigate files related to all users file called “ **NTUSER.DAT** ” it holds “ **UserAssist** ” so, After I saw these files I figured out that only “ **Joker** ” has a program called “ **DCode.exe”.**

**But what is trick here!!  
**I found another program called **dd.exe** it’s same program but with alternative name

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*oU7d5o9-ToJWlamWDPZE8g.png)

2 apps

(**\*\*Hint => try to hash them and compare**)

so, lets investigate “ **UserAssist** ” to see it

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*lZ-PCbctYd1k3dl-F2t6LQ.png)

dd.exe

This “ **NTUSER.DAT** ” that hold these info is located at F:\\Users\\Joker\\NTUSER.DAT

Here we go, the answer is: **user is Joker**

**Eleventh Question**: How many times was it used?

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*lZ-PCbctYd1k3dl-F2t6LQ.png)

dd.exe

See **Run Counter** column

Here we go, the answer is: **1**

**Twelfth Question**: When was it last used?

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*hyl50uWQLcaCtF0v0ZzvDw.png)

dd.exe

See **Last Executed** column

Here we go, the answer is: **2019–02–15 05:02:12**

**Thirteenth Question:** Where was the application located (full path)?

![](https://miro.medium.com/v2/resize:fit:1400/format:webp/1*hyl50uWQLcaCtF0v0ZzvDw.png)

dd.exe

See **Program Name** column

Here we go, the answer is: **C:\\Users\\Joker\\dd.exe**

**\*\*Note If there are any mistakes I did please don’t hesitate to spotlight on it to re-learn it because I’m still beginner.**

At the end,  
I hope you enjoyed this writeup ❤️.

## Stay in touch

[LinkedIn](https://www.linkedin.com/in/alii2laa/)
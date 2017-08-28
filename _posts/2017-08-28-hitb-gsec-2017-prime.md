---
title: 'HITB GSEC 2017: Prime (Mobile)'
layout: post
date: '2017-08-28'
tags:
- CTF
- writeup
- HITB GSEC 2017
- Mobile
comments: true
---

> Do you know prime? 
> 
> [Download Attachments](/files/b48bfaf7-d728-4ae3-94b7-cd8b2e6e9077.pcap)

In this challenge, we are given an apk file. Let's start off by using JADX to decompile it so that we can perform further examination of the code.

![]()

```java
package com.iromise.prime;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {
    private static long f14N = ((long) Math.pow(10.0d, 16.0d));

    class C01931 implements OnClickListener {
        C01931() {
        }

        public void onClick(View view) {
            Toast.makeText(MainActivity.this, "HITB{" + MainActivity.this.CalcNumber(MainActivity.f14N) + "}", 0).show();
        }
    }

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView((int) C0194R.layout.activity_main);
        Button start = (Button) findViewById(C0194R.id.start);
        Log.i("Number", String.valueOf(f14N));
        start.setOnClickListener(new C01931());
    }

    private Boolean isOk(long n) {
        if (n == 1) {
            return Boolean.FALSE;
        }
        if (n == 2) {
            return Boolean.TRUE;
        }
        for (long i = 2; i * i < n; i++) {
            if (n % i == 0) {
                return Boolean.FALSE;
            }
        }
        return Boolean.TRUE;
    }

    private long CalcNumber(long n) {
        long number = 0;
        for (long i = 1; i <= n; i++) {
            if (isOk(i).booleanValue()) {
                number++;
            }
        }
        return number;
    }
}
```

Once we decompile the apk, we are able to find `MainActivity.java` (above) in `com/iromise/prime/`. At first glance, there are a number of methods that interest us.

```java
public void onClick(View view) {
	Toast.makeText(MainActivity.this, "HITB{" + MainActivity.this.CalcNumber(MainActivity.f14N) + "}", 0).show();
}
```

First and foremost, we observe that `onClick()` prints the flag when it is run. It computes the flag by calling `CalcNumber` with `f14N` as the parameter. `f14N` is defined above as `Math.pow(10.0d, 16.0d)`, which is evaluates to $$10^{16}$$.

```java
private long CalcNumber(long n) {
	long number = 0;
	for (long i = 1; i <= n; i++) {
		if (isOk(i).booleanValue()) {
			number++;
		}
	}
	return number;
}
```

The function `CalcNumber()` loops over the range $$1$$ to $$10^{16}$$ and maintains a count of integers (`number`) in the aforementioned range that fulfils the condition imposed by `isOk()`.

```java
private Boolean isOk(long n) {
	if (n == 1) {
		return Boolean.FALSE;
	}
	if (n == 2) {
		return Boolean.TRUE;
	}
	for (long i = 2; i * i < n; i++) {
		if (n % i == 0) {
			return Boolean.FALSE;
		}
	}
	return Boolean.TRUE;
}
```

At first glance, the function `isOk` seems to be checking if a number is prime. However, one little detail that we need to pay attention to is the use of `<` instead of `<=` in the terminating condition of the `for` loop. Because of this nuance, it is accepting both prime numbers and squares of prime numbers. Let's illustrate this with an example:

consider $$n = 26$$,

If we use `<=` in the terminating condition,

```java
for (long i = 2; i * i <= n; i++) {
	if (n % i == 0) {
		return Boolean.FALSE;
	}
}

/*
2, 3, 5, 7, 11, 13, 17, 19, 23 would pass as they are all primes.
*/
```

If we omit the `<` as per this challege,

```java
for (long i = 2; i * i < n; i++) {
	if (n % i == 0) {
		return Boolean.FALSE;
	}
}

/* 
2, 3, 4, 5, 7, 9, 11, 13, 17, 19, 23, 25 would pass.

4, 9, 25 also passes because they are squares of prime numbers:

2 * 2 = 4
3 * 3 = 9
5 * 5 = 25 
*/
```

Given that $$\pi(n)$$ evaluates to the number of primes `<=` $$n$$, the number that `CalcNumber(n)` evaluates to is effectively $$\pi(10^{16}) + \pi(10^{8})$$.

![](/images/prime/image01.png)

As seen above, these values are readily available on [wikipedia](https://en.wikipedia.org/wiki/Prime-counting_function#Table_of_.CF.80.28x.29.2C_x_.2F_ln_x.2C_and_li.28x.29). As such, we can sum the required values to get our flag.

$$279238341033925 + 5761455 = 279238346795380$$

Flag: `HITB{279238346795380}`

<script type="text/javascript" async
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-MML-AM_CHTML">
</script>

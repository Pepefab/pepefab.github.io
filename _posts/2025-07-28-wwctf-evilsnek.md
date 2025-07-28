---
layout: post
category: [jail]
title: "WWCTF 2025 - Evil Snek"
author: pepefab
date: 2025-07-14 21:00:00 +0200
---

# WWCTF 2025 - Evil Snek

As a pyjail enjoyer, this was my favorite challenge of this CTF due to how simple the solution can be.

## The challenge

We're given the following Python 3 jail:

```python
#!/usr/bin/python3

def blacklist(cmd):
    if cmd.isascii() == False:
        return True
    bad_cmds = ['"',
                "'",
                "print",
                "_",
                ".",
                "import",
                "os",
                "lambda", 
                "system",
                "(",
                ")",
                "getattr",
                "setattr",
                "globals",
                "builtins",
                "input",
                "compile",
                "eval",
                "exec",
                "open",
                "read"]
    for i in bad_cmds:
        if i in cmd:
            return True
    return False
while True:
    inp = input("> ")
    if not blacklist(inp):
        try:
            exec(inp)
        except Exception as e:
            print("snek says: Error!")
            exit(0)
    else:
        print("snek says: Blacklisted!")
        exit(0)
```


There are two important things to take into account:
- It uses the base form of `exec()`
- There is a very restrictive blacklist function used to block key words


## Solving

With `exec()`, you can define the namespace (defined functions, variables, builtins...), and if not given, the current namespace is being passed. This means that any variable or function defined when `exec()` is called will be reachable from inside it, and this includes the `blacklist()` function !

As `blacklist()` is being called, we can't just set `blacklist = None` as it will make the `exec()` call crash due to calling `None()`, which is invalid. The idea is to find a function that takes one argument and returns False. The function `callable` does just that.

```
blacklist=callable
```

This means that when the jail calls

```
if not blacklist(inp):
```

It becomes

```
if not callable(inp):
```

Which pass the test, executing anything we want.


The full payload is used is:

```
> blacklist=callable
> import glob
> print(glob.glob("*"))
['run', 'flag.txt']
> print(open("flag.txt","r").read())
wwf{s1lly_sn3k_1_just_0verwr1t3_y0ur_funct10n}
```

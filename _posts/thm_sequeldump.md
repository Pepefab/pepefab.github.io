---
layout: post
category: [forensics, tryhackme]
title: "Sequel Dump"
author: pepefab
date: 2025-07-14
---

# TryHackMe - Sequel Dump

This CTF is about retrieving data stolen by SQLMap using only the PCAP containing SQLMap's requests.

## Analysis

We're given a PCAP containing requests from SQLMap, which has been used to steal sensitive information.

<a href="/assets/img/thm/sequeldump/wireshark.png" data-lity class="sx-center">
    <img src="/assets/img/posts/sequeldump/wireshark.png"/>
</a>

Using Wireshark's object export feature (File > Export Objects > HTTP > save all), we can export every request/response to multiple files.

The requests can be URL decoded with CyberChef to have a clearer view of what they are about.

<a href="/assets/img/thm/sequeldump/cyberchef.png" data-lity class="sx-center">
    <img src="/assets/img/posts/sequeldump/cyberchef.png"/>
</a>

Multiple types of sql injection methods are used, but one type of injection caught my eye as it dumps 'name' and 'description' from 'profiles'.

```
1 AND ORD(MID((SELECT IFNULL(CAST(CHAR_LENGTH(`name`) AS NCHAR),0x20) FROM profile_db.`profiles` ORDER BY id LIMIT 6,1),2,1))>49'
```

This sql injection can be split into smaller parts to make it easier to understand:

```
SELECT IFNULL(CAST(CHAR_LENGTH(`name`) AS NCHAR),0x20) FROM profile_db.`profiles` ORDER BY id LIMIT 6,1
```

This parts dump the 'name' field of the 6th row in table 'profiles'.

```
MID(<select_request>,2,1)
```

The MID function allows retrieval of the 2nd character of the name.

```
ORD(<character>)>49
```

And finally, this condition will return true if the ordinal of that character is superior to 49 ("1"), will make the whole request fail if false. SQLMap determines the character at each position by incrementally testing ordinal values. The lowest value that still results in a failed condition indicates the correct ordinal for the current character. 

To determine if the request succeeded (character is superior to X) or failed (character = X), we can look at the content length, as a request that succeeded will contains additional information. 

As sqlmap increment the tested value until it fails, this means we can solve it just by analysing only the failed requests (short reply), in particular the lowest number that failed.

## Solving

```
import glob
import re
import os


if __name__ == "__main__":

    fields = ["description", "name"]

    for field in fields:
        entries = {}
        for f in glob.glob(f"sql/search.php%3fquery=1%20AND%20ORD%28MID%28%28SELECT%20IFNULL%28CAST%28%60{field}%60%20AS%20NCHAR%29%2C0x20%29%20FROM%20profile_db.%60profiles%60%20ORDER%20BY%20id%20LIMIT*"):
            if os.path.getsize(f) > 100:
                # the request succeeded, it's not interesting
                continue

            # i = id of the row
            # j = offset of current character in the field
            # nb = ord being tested for this char
            i, j, nb = re.search(r"LIMIT%20(\d+)%2C\d+%29%2C(\d+)%2C\d+%29%29%3E(\d+)", f).groups()
            i = int(i)
            j = int(j)
            nb = int(nb)

            entries.setdefault(i, {})
            if j in entries.setdefault(i, {}):
                entries[i][j] = min(entries[i][j], nb)
            else:
                entries[i][j] = nb

        for _, entry in entries.items():
            value = []
            for j in range(1, len(entry)+1):
                try:
                    value.append(chr(entry[j]))
                except KeyError: # special case for '
                    value.append("'")
            print("".join(value))
```

This outputs all row values for fields 'name' and 'description', including the flag.

<a href="/assets/img/thm/sequeldump/solved.png" data-lity class="sx-center">
    <img src="/assets/img/posts/sequeldump/solved.png"/>
</a>

## Conclusion

I enjoyed this challenge, for which the goal and means were clear from the start, and it was just only a matter of understanding how SQLMap's enumeration process works. This is also my first public writeup on this blog... yay :)

# powerpacker_src

```
POWER-PACKER 36.10 (28.9.93) Data Cruncher.
  Written by Nico François (POWER PEAK)
  Decompiled by Dr. MefistO in 2020
  Version: v1.0

Usage : Crunch <source> <destination> [-e=EFFICIENCY] [-c=PASSWORD] [-o] [-h]
With:
  EFFICIENCY: 1 = Fast, 2 = Mediocre, 3 = Good (def), 4 = Very Good, 5 = Best
    PASSWORD: Encrypt file. Max 16 characters
          -o: Use it to compress with the old PP alorithm.
              The difference in the size of a window:
              - Old version: 0x4000
              - New version: 0x8000
          -h: Show this help

PowerPacker by Nico François (decompiled source code)
```

# History

I've decompiled the original library and restored source code of the original compression algo (including the encryption).

# Screnshots

![](/img/file1.png?raw=true)

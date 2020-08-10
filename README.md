# powerpacker_src

```
POWER-PACKER 36.10 (28.9.93) Data Cruncher.
  Written by Nico François (POWER PEAK)
  Decompiled by Dr. MefistO in 2020
  Version: v1.0

  Crunch: powerpack <source> <destination> <-c> [-e=EFFICIENCY] [-p=PASSWORD] [-o] [-h]
Decrunch: powerpack <source> <destination> <-d> [-p=PASSWORD] [-h]
With:
          -c: Crunch (compress)
          -d: Decrunch (decompress)
  EFFICIENCY: 1 = Fast, 2 = Mediocre, 3 = Good (def), 4 = Very Good, 5 = Best
    PASSWORD: Encrypt/decrypt file. Max 16 characters
          -o: Use it to compress with the old PP alorithm.
              The difference in the size of a window:
              - Old version: 0x4000
              - New version: 0x8000
          -h: Show this help
```

# History

I've decompiled the original library and restored source code of the original compression algo (including the encryption).

# Screenshots

![](/img/file1.png?raw=true)

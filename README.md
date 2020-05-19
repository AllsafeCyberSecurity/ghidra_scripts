# shellcode_hashes

shellcode_hashs was created inspired by a [script of the same name in flare](https://github.com/fireeye/flare-ida/tree/master/shellcode_hashes).   
Find the name that matches the [hash](https://www.fireeye.com/blog/threat-research/2012/11/precalculated-string-hashes-reverse-engineering-shellcode.html) used in the shellcode.  
Use the database created by flare script.

## sqlite2json.py
Since Ghidra could not import sqlite, I created a script to convert it to json.  
Convert with the following command:
```
python sqlite2json.py
```

## shellcode_hash_search.py

Open the target shellcode and execute the script.

![ch03_shellcodehash](https://user-images.githubusercontent.com/18203311/64575824-a5bf6700-d3b0-11e9-8294-c6b045c127a5.png)


![ch03_shellcodehash_decompile](https://user-images.githubusercontent.com/18203311/64575814-9c35ff00-d3b0-11e9-8cb8-3b686ae553a9.png)

# non-zero_xor_search.py
Finds XOR instructions whose source and destination operands are not equivalent.  
It is registered in the bookmark.

![ch03_non-zero_xor](https://user-images.githubusercontent.com/18203311/64575818-9fc98600-d3b0-11e9-8732-bccf8d0e3c1f.png)

# coloring_call_jmp.py

Coloring of CALL and JMP instructions.  
Color the following instructions
 * CALL　 
 * JE
 * JZ
 * JNE
 * JNZ
 * JA
 * JAE
 * JBE
 * JB
 * JL
 * JLE
 * JG
 * JGE

![ch03_coloring_call_jmp](https://user-images.githubusercontent.com/18203311/64575795-87596b80-d3b0-11e9-847b-f46ab6aefa4b.png)

# stackstrings.py

Deobfuscate stackstrings used by Godzilla Loader.

### before
![stackstrings_execute_before](https://user-images.githubusercontent.com/18203311/65371013-13fe0680-dc9a-11e9-910a-37329767a26a.png)

### after
![stackstrings_execute_after](https://user-images.githubusercontent.com/18203311/65371015-15c7ca00-dc9a-11e9-80c2-5028a8c3d03f.png)

### console output
![stackstrings_console_result](https://user-images.githubusercontent.com/18203311/65371016-16f8f700-dc9a-11e9-981c-552a7e9152a4.png)

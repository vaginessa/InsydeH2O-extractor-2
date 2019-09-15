version 0.31+genBTC - extract InsydeFlash (isflash.bin) - now handles platforms.ini and EC.bin also<p>
Usage:<br>
<p>
EXTRACT All:<br>
"extractor.exe"<br>
-(will extract biosfile.fd, platforms.ini, ec.bin)<br>
-(by default, extracts from isflash.bin)<br>
"extractor.exe someothername.bin"<br>
-(can specify alternate name to extract from)<br>
<p>
CAN REPLACE Platforms.ini<br>
"extractor.exe isflash.bin replace ini"<br>
-(enters replace mode when 3 parameters given, 1st must be the target bios file.)<br>
-(the other filenames are not specifyable yet, for simplicity purposes)<br>
-(It will overwrite/modify the target file directly (you should make a backup first)<br>
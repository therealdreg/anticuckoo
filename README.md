# anticuckoo
A tool to detect and crash Cuckoo Sandbox. A boring Sunday...

## Features 
Tested in Cuckoo Sandbox Official and Accuvant version:
* Cuckoo hooks detection (all kind of cuckoo hooks).
* Suspicius data in own memory (without APIs, page per page scanning).

Submit Release/anticuckoo.exe to analysis in Cuckoo Sandbox. Check the screenshots (console output) or in Accesed Files in Sumary.

![ScreenShot](https://github.com/David-Reguera-Garcia-Dreg/anticuckoo/blob/images/anticuckoo.png)

![ScreenShot](https://github.com/David-Reguera-Garcia-Dreg/anticuckoo/blob/images/Sumary.png)

## TODO
* Python process & agent.py detection - 70% DONE
* Improve hook detection checking correct bytes in well known places (Ex Native APIs always have the same signatures etc.).
* Cuckoo's TLS entry detection.

New ideas & PRs are wellcome.

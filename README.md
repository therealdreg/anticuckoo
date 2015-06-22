# anticuckoo
A tool to detect and crash Cuckoo Sandbox. Tested in Cuckoo Sandbox Official and Accuvant version.

## Features 

* [Detection](#cuckoo-detection):
  * Cuckoo hooks detection (all kind of cuckoo hooks).
  * Suspicius data in own memory (without APIs, page per page scanning).
* [Crash (Execute with arguments)](#cuckoo-crash):
  * -c1:

[Click here to view TODO](#TODO)

### Cuckoo Detection

Submit Release/anticuckoo.exe to analysis in Cuckoo Sandbox. Check the screenshots (console output). Also you can check Accesed Files in Sumary:

![ScreenShot](https://github.com/David-Reguera-Garcia-Dreg/anticuckoo/blob/images/anticuckoo.png)

Accesed Files in Sumary (django web):

![ScreenShot](https://github.com/David-Reguera-Garcia-Dreg/anticuckoo/blob/images/Sumary.png)

### Cuckoo Crash

Specify in submit options the argument, ex via django web: -c1

![ScreenShot](https://github.com/David-Reguera-Garcia-Dreg/anticuckoo/blob/images/cuckooarguments.png)

And check Screenshots or connect via RDP or whatson connection to view the crash:

![Screenshot](https://github.com/David-Reguera-Garcia-Dreg/anticuckoo/blob/images/cuckoocrash.png)

## TODO
* Python process & agent.py detection - 70% DONE
* Improve hook detection checking correct bytes in well known places (Ex Native APIs always have the same signatures etc.).
* Cuckoo's TLS entry detection.

New ideas & PRs are wellcome.

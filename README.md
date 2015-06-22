# anticuckoo
A tool to detect and crash Cuckoo Sandbox. Tested in Cuckoo Sandbox Official and Accuvant version. 

## Features 

* [Detection](#cuckoo-detection):
  * Cuckoo hooks detection (all kind of cuckoo hooks).
  * Suspicius data in own memory (without APIs, page per page scanning).
* [Crash (Execute with arguments)](#cuckoo-crash) (out of a sandbox these POCs dont crash the program):
  * -c1: Modify the RET N instruction of a hooked API with a higher value. Next call to API with more PUSH instruction. If the hooked API is called from the Cuckoo's HookHandler with its own stack frame and the original API ARGs... CRASH!.

[TODO list](#todo)

### Cuckoo Detection

Submit Release/anticuckoo.exe to analysis in Cuckoo Sandbox. Check the screenshots (console output). Also you can check Accesed Files in Sumary:

![ScreenShot](https://github.com/David-Reguera-Garcia-Dreg/anticuckoo/blob/images/anticuckoo.png)

Accesed Files in Sumary (django web):

![ScreenShot](https://github.com/David-Reguera-Garcia-Dreg/anticuckoo/blob/images/Sumary.png)

### Cuckoo Crash

Specify in submit options the crash argument, ex **-c1** (via django web):

![ScreenShot](https://github.com/David-Reguera-Garcia-Dreg/anticuckoo/blob/images/cuckooarguments.png)

And check **Screenshots/connect via RDP/whatson connection** to verify the crash. Ex **-c1** via RDP:

![Screenshot](https://github.com/David-Reguera-Garcia-Dreg/anticuckoo/blob/images/cuckoocrash.png)

## TODO
* Python process & agent.py detection - 70% DONE
* Improve hook detection checking correct bytes in well known places (Ex Native APIs always have the same signatures etc.).
* Cuckoo's TLS entry detection.

New ideas & PRs are wellcome.

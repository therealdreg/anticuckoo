# anticuckoo
A tool to detect and crash Cuckoo Sandbox. Tested in [Cuckoo Sandbox Official](http://www.cuckoosandbox.org/) and [Accuvant's Cuckoo version](https://github.com/brad-accuvant/cuckoo-modified). 

Please, consider make a donation: https://github.com/sponsors/therealdreg

Anticuckoo can also detect other sandbox like FireEye (-c2):

![ScreenShot](https://github.com/David-Reguera-Garcia-Dreg/anticuckoo/blob/images/fireyee.png)

[Reddit / netsec discussion about anticuckoo.](https://www.reddit.com/r/netsec/comments/3atvmb/anticuckoo_a_tool_to_detect_and_crash_cuckoo/)

## Features 

* [Detection](#cuckoo-detection):
  * Cuckoo hooks detection (all kind of cuckoo hooks).
  * Suspicius data in own memory (without APIs, page per page scanning).
* [Crash (Execute with arguments)](#cuckoo-crash) (out of a sandbox these args dont crash the program):
  * -c1: Modify the RET N instruction of a hooked API with a higher value. Next call to API pushing more args into stack. If the hooked API is called from the Cuckoo's HookHandler the program crash because it only pushes the real API args then the modified RET N instruction corrupt the HookHandler's stack.
  * -c2: Cuckoomon run threads inside the process, when the tool detects new threads crash!.
  * -c3: Crashing when detects hook handler activity in the old stack area.

The overkill methods can be useful. For example using the overkill methods you have two features in one: detection/crash and "a kind of Sleep" (Cuckoomon bypass long Sleeps calls).

Crash POCs is only a demostration. A real malware can be use this code to detect cuckoo without crashing it, ex only check the exception, esp etc and after make useless code.

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

## Referenced by

* Stealthy, Hypervisor-based Malware Analysis - Tamas K Lengyel: https://www.slideshare.net/tklengyel/stealthy-hypervisorbased-malware-analysis
* Brad Spengler (grsecurity) nice words: https://github.com/brad-sp/community-modified/commit/29587d691242a9ba890877f623fdf2447fe4336f
* Reddit / netsec discussion about anticuckoo: https://www.reddit.com/r/netsec/comments/3atvmb/anticuckoo_a_tool_to_detect_and_crash_cuckoo/
* Multiple Instance Learning for Malware Classification - Jan Stiborek, Tomáš Pevný, Martin Rehák: https://arxiv.org/pdf/1705.02268.pdf
* To Catch a Ratter: Monitoring the Behavior of Amateur DarkComet RAT Operators in the Wild - Brown Farinholt, Mohammad Rezaeirad, Paul Pearce, Hitesh Dharmdasani, Haikuo Yin, Stevens Le Blondk, Damon McCoy, Kirill Levchenko: http://damonmccoy.com/papers/rat-sp17.pdf
* Hack&Beers Cadiz Análisis de Malware Cuckoo Sandbox - Mario Alberto Parra Alonso: https://www.slideshare.net/MarioAlbertoParraAlo/hackbeers-cadiz-anlisis-de-malware-cuckoo-sandbox
* Defense in Depth: Detonation Technologies: http://blog.inquest.net/blog/2018/03/12/defense-in-depth-detonation-technologies/
* Dynamic Reconfiguration of Intrusion Detection Systems - Jan Stiborek: https://dspace.cvut.cz/bitstream/handle/10467/73562/Disertace_Stiborek_2017.pdf
* New Dynamic Bypass Technique Working in Certain Environments Only: https://asec.ahnlab.com/en/16540/

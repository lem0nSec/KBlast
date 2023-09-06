# KBlast

__Windows Kernel Offensive Toolset__

-----------------------------------------------------------------------------------------------------------------------------------------------------------------
`KBlast` is a small application I built while experimenting with Windows kernel offensive security techniques. It puts together almost all the techniques discussed in the [Offensive Driver Development](https://training.zeropointsecurity.co.uk/courses/offensive-driver-development) course from Zero Point Security, plus some extra techniques. I thought that building up this tool rather than writing down a cheatsheet was a better way to both put into practice the concepts learned and provide the community with a comprehensive learning resource.

```
    __ __ ____  __           __
   / //_// __ )/ /___ ______/ /_        | KBlast client - OS Build #19045 - Major version #10
  / ,<  / __  / / __ `/ ___/ __/        | Version : 1.0 ( first release ) - Architecture : x64
 / /| |/ /_/ / / /_/ (__  ) /_          | Website : http://www.github.com/lem0nSec/KBlast
/_/ |_/_____/_/\__,_/____/\__/          | Author  : lem0nSec_
------------------------------------------------------->>>
KBlast > tokn|help

Commands - ' tokn ' ( token manipulation interactions )

        enablepriv:     Enable all privileges for a given process
        disablepriv:    Disable all privileges for a given process
             steal:     Steal token and give it to a given process
           restore:     Restore the original token of a given process

Examples:

$ tokn|enablepriv|123 - ( enable all privileges for process 123 )
$ tokn|disablepriv|123 - ( disable all privileges for process 123 )
$ tokn|steal|4|123 - ( replace 123's token with System's [ 4 ] )
$ tokn|restore|123 - ( restore 123's token [ ! experimental ! ] )

KBlast >
```
## How it works
This tool has two components. KBlaster.sys is the application's driver, the actual core where all central features reside. In contrast, KBlast.exe is the client application. KBlast.exe takes user commands, generate a specific input to be sent to KBlaster, and once the driver has finished its operation the client may or may not return the result of the operation depending on what was done.

## Commands and Features
KBlast commands can fall into four categories which must be prepended to the actual command (generic commands can be just typed and run right away). Categories can be:

- misc (misc functionalities, es. memory read/write)
- prot (protection PPL)
- tokn (token management)
- call (kernel callbacks)

The fun part is that some misc functionalities can be combined with commands from other modules, thus offering a chance to diversify already known approaches.


## Examples
The following screenshot shows the swapping of a high-integrity powershell token with a system-level token (System process pid 4).

![](pictures/token_stealing.png)


The following screenshot shows the elevation of mimikatz PPL to LSA. Mimikatz is now granted read access to lsass.

![](pictures/ppl_lsa.png)


## Installation Notes
Since KBlaster.sys is just a driver I built for my own learning, it does not come with signing. Disabling DSE with the following command is required to play with this tool.

- `bcdedit /set testsigning on`


## Important note :warning:
__This tool is still at an early stage of development.__ KBlast is being actively tested on a Windows 10 Pro build 19045 x64 machine. Some functionalities support other Windows versions. Others don't. Since the Windows Kernel is mostly composed of 'opaque' data structures, this tool is likely to trigger bsods at this stage of development if a version other than the one mentioned is used. Development of these tools often requires months. I hope you understand and appreciate the project and the idea behind!
Last but not least, I might consider adding new features such as process hiding if the project will turn out a useful resource for learners.
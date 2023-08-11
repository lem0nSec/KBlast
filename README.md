# KBlast\(er\)
**Windows Kernel Offensive Security Toolset**

-----------------------------------------------------------------------------------------------------------------------------------------------------------------
`KBlast(er)` is a small application composed of a Windows driver plus a client application. The tool combines some Windows ring0 offensive security techniques in one tool. After completing the course [Offensive Driver Development](https://training.zeropointsecurity.co.uk/courses/offensive-driver-development) from Zero Point Security, I decided to put together the techniques I learned plus some extra stuff in one single application rather taking notes or writing down a cheatsheet.

```
    __ __ ____  __           __
   / //_// __ )/ /___ ______/ /_        | KBlast client - OS Build #9200 - System time #19:36
  / ,<  / __  / / __ `/ ___/ __/        | Version : 1.0 ( first release )
 / /| |/ /_/ / / /_/ (__  ) /_          | Angelo Frasca Caccia ( lem0nSec_ )
/_/ |_/_____/_/\__,_/____/\__/          | Website: http://www.github.com/lem0nSec/KBlast
------------------------------------------------------->>>
KBlast > help

Module - ' Generic ' ( does not initiate kernel interactions )

        help            :       Show this help
        quit            :       Quit KBlast
        cls             :       Clear the screen
        banner          :       Print KBlast banner
        pid             :       Show current pid
        time            :       Display system time
        !{cmd}          :       Execute system command

KBlast >
```
## How it works
This tool has two parts. KBlaster.sys is the actual core where all central features live. Since the goal of the project was putting puting together Windows kernel offensive security techniques, there must be driver that is loaded onto the kernel space. On the other hand, KBlast.exe is the client application. KBlast.exe takes user commands, generate a specific input to be sent to KBlaster, and once the driver has finished its operation the client may or may not return the result of the operation depending on what has been done.

## Modules
Right now KBlast\(er\) supports five modules, which do not include generic commands. Modules are 'misc', 'prot', 'priv', 'tokn', 'call'. These modules reflect specific techniques. The fun part is that some misc functionalities can be combined to functionalities from other modules, thus offering a chance to diversify widely known techniques.

/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

// Windows versions
typedef enum {
    WindowsUnsupported,
    WindowsRedstone1,		// 14393,
    WindowsRedstone2,		// 15063,
    WindowsRedstone3,		// 16299,
    WindowsRedstone4,		// 17134,
    WindowsRedstone5,		// 17763
    Windows19h1, 			// 18362
    Windows19h2,			// 18363
    Windows20h1,			// 19041
    Windows20h2,			// 19042
    Windows21h1,			// 19043
    Windows21h2,			// 19044
    Windows22h2,            // 19045
    Windows23h2
} WindowsVersion;

const int EPROCESS_UNIQUEPROCESSID_OFFSET[] =
{
    0x00,       // WindowsUnsupported
    0x02E8,     // WindowsRedstore1
    0x02E0,     // WindowsRedstore2
    0x02E0,     // WindowsRedstore3
    0x02E0,     // WindowsRedstore4
    0x02E0,     // WindowsRedstore5
    0x02E8,     // Windows19h1
    0x0440,     // Windows19h2
    0x0440,     // Windows20h1
    0x0440,     // Windows20h2
    0x0440,     // Windows21h1
    0x0440,     // Windows21h2
    0x0440,      // Windows22h2
    0x0440
};

const int EPROCESS_SIGNATURE_LEVEL_OFFSET[] =
{
    0x00,		// WindowsUnsupported
    0x06C0,   	// WindowsRedstore1
    0x06C8,   	// WindowsRedstore2
    0x06C8,   	// WindowsRedstore3
    0x06C8,   	// WindowsRedstore4
    0x06C8,   	// WindowsRedstore5
    0x06F8,		// Windows19h1
    0x0878,  	// Windows19h2
    0x0878,   	// Windows20h1
    0x0878,   	// Windows20h2
    0x0878,   	// Windows21h1
    0x0878,   	// Windows21h2
    0x0878,    	// Windows22h2
    0x0878
};

const int EPROCESS_ACTIVEPROCESSLINKS_OFFSET[] =
{
    0x00,		// WindowsUnsupported
    0x02F0,   	// WindowsRedstore1
    0x06CA,   	// WindowsRedstore2
    0x02E8,   	// WindowsRedstore3
    0x02E8,   	// WindowsRedstore4
    0x02E8,   	// WindowsRedstore5
    0x02F0,		// Windows19h1
    0x0448,  	// Windows19h2
    0x0448,   	// Windows20h1
    0x0448,   	// Windows20h2
    0x0448,   	// Windows21h1
    0x0448,   	// Windows21h2
    0x0448,    	// Windows22h2
    0x0448
};

const int EPROCESS_IMAGEFILENAME_OFFSET[] =
{
    0x00,       // WindowsUnsupported
    0x0450,     // WindowsRedstore1
    0x0450,     // WindowsRedstore2
    0x0450,     // WindowsRedstore3
    0x0450,     // WindowsRedstore4
    0x0450,     // WindowsRedstore5
    0x0450,     // Windows19h1
    0x05A8,     // Windows19h2
    0x05A8,     // Windows20h1
    0x05A8,     // Windows20h2
    0x05A8,     // Windows21h1
    0x05A8,     // Windows21h2
    0x05A8,      // Windows22h2
    0x05A8
};

const int EPROCESS_SEAUDITPROCESSCREATIONINFO_OFFSET[] =
{
    0x00,		// WindowsUnsupported
    0x0468,   	// WindowsRedstore1
    0x0468,   	// WindowsRedstore2
    0x0468,   	// WindowsRedstore3
    0x0468,   	// WindowsRedstore4
    0x0468,   	// WindowsRedstore5
    0x0468,		// Windows19h1
    0x05C0,  	// Windows19h2
    0x05C0,   	// Windows20h1
    0x05C0,   	// Windows20h2
    0x05C0,   	// Windows21h1
    0x05C0,   	// Windows21h2
    0x05C0,    	// Windows22h2
    0x05C0
};

const int EPROCESS_TOKEN_OFFSET[] =
{
    0x00,		// WindowsUnsupported
    0x0358,   	// WindowsRedstore1
    0x0358,   	// WindowsRedstore2
    0x0358,   	// WindowsRedstore3
    0x0358,   	// WindowsRedstore4
    0x0358,   	// WindowsRedstore5
    0x0360,		// Windows19h1
    0x04B8,  	// Windows19h2
    0x04B8,   	// Windows20h1
    0x04B8,   	// Windows20h2
    0x04B8,   	// Windows21h1
    0x04B8,   	// Windows21h2
    0x04B8,    	// Windows22h2
    0x04B8
};

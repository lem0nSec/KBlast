/*
* Author:	Angelo Frasca Caccia ( lem0nSec_ )
* Title:	KBlaster.sys ( driver )
* Website:	https://github.com/lem0nSec/KBlast
*/


#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <aux_klib.h>
#include "navigation.hpp"
#include "KBlaster_k_utils.hpp"

#pragma warning(disable: 4996)

#define POOL_TAG 'lemS'
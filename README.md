# ZPP
A work in progress C preprocessor written in standard C99 with no external libraries required.

## Main features missing.
* `#include`.
* full `#if` support.
* `#pragma once`
* `#pragma (push/pop)_macro`

## Building.
To build it you must first run `vcvarsall.bat` and then run `nmake`.
For now building only works with MSVC on Windows however it could likely build elsewhere with a few changes. 

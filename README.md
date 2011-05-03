# moatool #

***moatool*** is a little library written in C to manage Mach-O archives on Mac OS, it allows to reduce them into a single binary or to split them.


## Usage ##

Just copy the *moatool.h* and *moatool.c* files to your project folder and you are ready to use it.

The file *example.c* contains all the code necessary to use it, just look at it.

If you want you can build a library, see below.


## Building a library ##

You can build a static or dynamic a library, but I recommend you to build a dynamic one, see example below.

### 1 - Building a static library (not recommended) ###

	gcc -c moatool.c -Wall -o moatool.o
	ar rcs libmoatool.a moatool.o

### 2 - Building a dynamic library (recommended) ###

	gcc moatool.c -dynamiclib -Wall -o libmoatool.dylib

Then to install the library, you can place it in */usr/local/lib/* or wherever you want.

If you decided to use ***moatool*** as a library, and install it in a directory that is in your *$PATH* environment, you simply have to tell gcc to link to the library like this :

	gcc YOUR_PROGRAM.c -lmoatool -o OUTPUT_PROGRAM
	
If the library isn't in your *$PATH* environment, you have to specify the path to gcc using the -L option, here is an example, assuming the library is located in your home folder :

	gcc YOUR_PROGRAM.c -L"/Users/YOU" -lmoatool -o OUTPUT_PROGRAM


## License ##

***moatool*** is released under the Simplified BSD license, see LICENSE.txt.

Benjamin Godard.

Blog : <http://www.cocoabyss.com/>

Twitter : @Nyx0uf

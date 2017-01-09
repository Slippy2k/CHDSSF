# CHDSSF
SSF with CHDv5 (Archive.org) Support

SSF is quite the amazing Saturn emulator, however, it lacks an (enabled) option to load from disc images without the use of some adware-infested solution such as DaemonTools.

Included is a patch started less than 24 hours ago that adds CHD support - no emulated drive needed.

Instructions:

Note: You can use your own SSF.exe from Test Ver, but you'll have to make a couple of minor edits to make it work.

1. Place WINM0.dll, libchd.dll, chdrom, and SSF.exe in the SSF emulator (Test Ver) directory.

2. Run SSF.exe with a command argument that contains the relative (or absolute, whatever) path to the chd file.
	e.g.
	```
	"SSF.exe bomb.chd"
	```
3. SSF should start (and so should the game), if it doesn't, check the disc drive selected under Options, it should be set to "CHDDriveVirtual", if not, set it and select "CD Close" from the Hardware drop-down.

Note2: This is super messy and probably won't work with everything, the 5 or so games I tried worked perfectly, but who knows.
I plan on cleaning this up later and adding more options.

Happy Saturn'ing ^^

![Image of CHDSSF](http://i.imgur.com/ad9G42E.png)

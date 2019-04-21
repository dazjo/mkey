mkey
====

[![forthebadge](http://forthebadge.com/images/badges/built-with-resentment.svg)](http://forthebadge.com)

mkey is a master key generator for the Parental Controls functionality on various consoles from a *certain vendor*. Currently, this includes the Wii, DSi, 3DS, Wii U and Switch.

This allows resetting Parental Controls (due to being locked out) without having to contact customer support.

If you would just like to **use** this, with no concern for the code or how it works, visit: https://mkey.salthax.org/

v2 support was initially implemented in October 2015, and has been serving the above page since December 2015. v1 and Wii U support was added in January 2016. v0 support was added in April 2016. v3/Switch support was added in July 2017. v4 support was added in April 2019.

Python and C implementations are available in this repository. These function very similarly.

As of writing, system support is good - all algorithms in use are supported, provided one can extract the necessary keys from the system firmware.

For some algorithm versions (especially 3DS v2) many keys are required from the system firmware in order to generate master keys. These can differ between regions and system versions. The best documentation for these is in the code, which covers the situation on all supported devices.

The v4 algorithm on the Switch and likely any future algorithms also require a console-unique device ID stored on the system that Nintendo can retrieve using the separate, visible serial number one must provide via the support call. The security in this relies upon the device ID being hard to obtain by simply using the device. This would make the generator more of an academic exercise rather than a practical tool.

Some 3DS-specific documentation on the algorithms seen so far can be found at: https://3dbrew.org/wiki/System_Settings#Parental_Controls_Reset

## License

mkey is distributed under the AGPLv3 license, see [LICENSE](LICENSE).

ctr.c, ctr.h, utils.c and utils.h are taken from [ctrtool](https://github.com/profi200/Project_CTR/tree/master/ctrtool), which is licensed under MIT, see [LICENSE-ctrtool](LICENSE-ctrtool).

## Credits

* marcan for the Wii reset tool: https://wii.marcan.st/parental
* neimod for the 3DS v0 reset tool: https://github.com/3dshax/ctr/commit/bcb3734b9a26d0fe7ef66f7d3814406fee797303
* SALT greetz: WulfyStylez and Shiny Quagsire (^:

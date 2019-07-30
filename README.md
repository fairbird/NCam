NCam: Open Source Conditional Access Module
============================================


License
=======

NCam: Open Source CAM
Copyright (C) 2012-2018 developed by Javilonas.

NCam is based on the Oscam 1.20: http://www.streamboard.tv/svn/oscam/trunk/

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

For the full text of the licese, please read COPYING file in NCAm
top directory or visit http://www.gnu.org/licenses/gpl-3.0.html


How to build NCAM?:
===================


              Building NCAM                     
================================================

The NCAM building (compilation) process is fairly straight forward.

- "build_ncam.sh" tool to perform compiling quick and easy way for everyone.

- First of all, you need to clone the repository NCAM on your system:

1 - Clone NCam git in /home/$username
=

git clone git://github.com/javilonas/NCam.git -b master

2 - Switch to folder NCam (/home/$username/NCam)
=

cd NCam

3 - Run the tool attached for compilation.
=

sh build_ncam.sh

![ScreenShot](http://i67.tinypic.com/mi2ccg.jpg)

4 - Select the desired option
=

For example, to compile all, choose option 1 and press enter

5 - The binary will be built in /home/$username/NCam/Distribution directory after their construction.
=

;)

----------------------------------------------------

If you want to compile the system witch more or less options:
=============================================================

make menuconfig

- When finished, save the changes and compile NCAM with the tool provided.



This information will be expanded soon.

For questions, contact in the support forum: https://www.lonasdigital.com









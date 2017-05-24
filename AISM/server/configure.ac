#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

#AC_PREREQ([2.69])
#AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])

AC_INIT(myserver.cpp)
AM_INIT_AUTOMAKE(myserver, 1.0)
# AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
# AC_CHECK_FUNCS([inet_ntoa memset select socket])

# enable debug or not                                                           
# AC_ARG_ENABLE(feature, help-string, [action-if-given], [action-if-not-given])
AC_ARG_ENABLE(debug, AS_HELP_STRING([--enable-debug], [enable DEBUG mode(default=no)]),
                [],
				[enable_debug=no])
# AS_IF (test1, [run-if-true1], . . . , [run-if-false])
AS_IF([test "x$enable_debug" = "xyes"], [CXXFLAGS="-g2 -O0 -DDEBUG -Wall"],
	  [test "x$enable_debug" = "xno"], [CXXFLAGS="-O2 -Wall"],
	  [])
# 上述配置的意思是：给最后生成的configure脚本添加一个--enable-debug选项，
# 如果指定了此选项，则CXXFLAGS="-g3 -O0 -DDEBUG -Wall"，否则CXXFLAGS="-O2 -Wall"。
# 每一个enable选项都有一个enable_feature变量与之对应，可以通过此变量取得用户指定的值。以上面的场景为例：
# （1）如果指定--enable-debug，不带参数，则enable_debug变量值为"yes"。
# （2）如果指定--enable-debug=no，则enable_debug变量值为"no"。
# （3）如果指定--disable-debug，则与--enable-debug=no效果相同。

AC_OUTPUT(Makefile)

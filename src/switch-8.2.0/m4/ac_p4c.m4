# SYNOPSIS
#
#   SET_P4C()
#
# DESCRIPTION
#
#   Check p4c version and set the following variables in the environment:
#
#   This macro should not be called within an if statement.
#
#   P4C               -- path to p4c compiler
#   P4C_VERSION       -- compiler version
#   P4C_VERSION_MAJOR -- the major version of the compiler
#
#   In addition, the following automake conditionals are set:
#
#   WITH_P4C_DEFAULT  -- the default version of the compiler
#   WITH_P4C_LEGACY   -- v5 compiler
#   WITH_P4C_ALPHA    -- v6 or later

AC_DEFUN([SET_P4C], [
  P4C_="$P4C"
  # unlike AC_CHECK_PROG, AC_PATH_PROG will run even if the variable (P4C) is
  # already set
  AC_PATH_PROG([P4C], ["$P4C"], [], [$BIN_DIR$PATH_SEPARATOR$PATH])
  AS_IF([test x"$P4C" = x],
      [AS_IF([test x"P4C_" != x],
        [AC_MSG_NOTICE([cannot find P4 compiler "$P4C_"])])],
        [P4C_VERSION=`$P4C --version 2>&1 | tail -n1 | sed -e's/p4c//'`])
AC_SUBST([P4C_VERSION])
AC_SUBST([P4C_VERSION_MAJOR], [`echo $P4C_VERSION | cut -f 1 -d '.'`])
AM_CONDITIONAL([WITH_P4C_LEGACY], [ test "$P4C_VERSION_MAJOR" = "5"])
AM_CONDITIONAL([WITH_P4C_ALPHA],  [ test "$P4C_VERSION_MAJOR" != "5"])
AM_CONDITIONAL([WITH_P4C_DEFAULT],[ test "$P4C_VERSION_MAJOR" = "5" ])
AS_IF([test x"$P4C" != x],
    [AC_MSG_NOTICE("Found compiler $P4C version $P4C_VERSION")])
])

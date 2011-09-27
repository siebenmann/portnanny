#
# You cannot run this directly. Don't even try.
# This is not a real distutils setup, since it assumes we are going
# to be running it from one level up, despite where it lives.
#
from distutils.core import setup, Extension

setup(name = "group",
      version = '0.0',
      description = 'Unix group manipulation module',
      ext_modules = [Extension("group", ["group/group.c"])],
      )

/**********************************************************************
Copyright (C) 2000 Christopher Craig

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
**********************************************************************/
/* $Id: group.c,v 1.6 2000/06/07 20:06:21 ccraig Exp $ */


#include "Python.h"
#include <unistd.h>
#include <grp.h>
#include <sys/types.h>

static PyObject *ErrorObject;


static PyObject *
group_error()
{
     return PyErr_SetFromErrno(PyExc_OSError);
}


static char group_initgroups__doc__[] =
"initgroups(username, gid) -> None\n\n\
Set the current process's groups by looking up all groups for username.";

static PyObject *
group_initgroups(self, args)
PyObject *self;
PyObject *args;
{
     char *username;
     gid_t  gid;

     if(!PyArg_ParseTuple(args, "sl", &username, &gid))
	  return NULL;
	
     if(initgroups(username, gid) == -1)
	  return group_error();

     Py_INCREF(Py_None);
     return Py_None;
}

static char group_setgroups__doc__[] =
"setgroups((gid, ...)) -> None\n\n\
Add groups to the supplemental groups list for this process.";

static PyObject *
group_setgroups(self, args)
PyObject *self;
PyObject *args;
{
     int argc, i;
     int *argvlist;
     PyObject *argv;
     PyObject *(*getitem) Py_PROTO((PyObject *, int));

     if (!PyArg_ParseTuple(args, "O", &argv))
	  return NULL;

     if (PyList_Check(argv)) {
	  argc = PyList_Size(argv);
	  getitem = PyList_GetItem;
     } else if (PyTuple_Check(argv)) {
	  argc = PyTuple_Size(argv);
	  getitem = PyTuple_GetItem;
     } else {
     badarg:
	  PyErr_BadArgument();
	  return NULL;
     }

     argvlist = PyMem_NEW(int, argc);
     if(argvlist==NULL)
	  return NULL;
     for(i=0; i<argc; i++) {
	  if(!PyArg_Parse((*getitem)(argv, i), "i", &argvlist[i])) {
	       PyMem_DEL(argvlist);
	       goto badarg;
	  }
     }

     
     if(setgroups(argc, argvlist)==-1) {
	  PyMem_DEL(argvlist);
	  return group_error();
     }
     PyMem_DEL(argvlist);
     Py_INCREF(Py_None);
     return Py_None;

}


static char group_getgroups__doc__[] =
"getgroups() -> (gid, ...)\n\n\
Returns a tuple containing all of the supplementary groups for this process";


static PyObject *
group_getgroups(self, args)
PyObject *self;
PyObject *args;
{
     int i, ngroups;
     int *groups;
     PyObject *rettuple;

     if(!PyArg_ParseTuple(args, ""))
	  return NULL;

     ngroups = getgroups(0, NULL);
     groups = malloc(sizeof(int)*ngroups);
     if((ngroups = getgroups(ngroups, groups))==-1) {
	  free(groups);
	  return group_error();
     }

     if((rettuple = PyTuple_New(ngroups))==NULL) {
	  free(groups);
	  return NULL;
     }

     for(i=0; i<ngroups; i++) 
	  PyTuple_SetItem(rettuple, i, PyInt_FromLong((long)groups[i]));

     free(groups);
     return rettuple;
}
     
     
static PyMethodDef group_methods[] = {
     {"initgroups",group_initgroups, METH_VARARGS, group_initgroups__doc__},
     {"setgroups", group_setgroups, METH_VARARGS, group_setgroups__doc__},
     {"getgroups", group_getgroups, METH_VARARGS, group_getgroups__doc__}
};

static char group_module_documentation[] =
"This module provides support for the supplemental groups systems on\n"
"modern Unicies.  It provides methods with access to the syscalls:\n"
"getgroups(), setgroups(), and initgroups().\n\n"
"Copyright (C) 2000 Christopher Craig";

void initgroup()
{
     PyObject *m, *d;
     
     m = Py_InitModule4("group", group_methods, group_module_documentation,
					(PyObject*)NULL,PYTHON_API_VERSION);

     d = PyModule_GetDict(m);
     ErrorObject = PyString_FromString("group.error");
     PyDict_SetItemString(d, "error", ErrorObject);

     /* Check for errors */
     if (PyErr_Occurred()) 
	  Py_FatalError("can't initialize module group");

}

	

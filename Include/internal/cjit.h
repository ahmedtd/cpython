#ifndef Py_INTERNAL_CJIT_H
#define Py_INTERNAL_CJIT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "frameobject.h"

PyAPI_FUNC(void) _PyJIT_JITCodeGen(PyFrameObject *f);

#ifdef __cplusplus
}
#endif

#endif /* !Py_INTERNAL_CJIT_H */

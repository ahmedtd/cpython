// This file will preprocessed with dynasm

#include "Python.h"
#include "internal/pystate.h"

#include "code.h"
#include "frameobject.h"
#include "opcode.h"

#include "./dynasm/dasm_proto.h"
#include "./dynasm/dasm_x86.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>

static void
link_and_encode(dasm_State **d, void **jitcode_buf, size_t *jitcode_size) {
    dasm_link(d, jitcode_size);

    *jitcode_buf = mmap(0,
                        *jitcode_size,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1,
                        0);

    dasm_encode(d, *jitcode_buf);

    mprotect(*jitcode_buf, *jitcode_size, PROT_READ | PROT_EXEC);
}

// Write JITed code into the frame object
void _PyJIT_JITCodeGen(PyFrameObject *f)
{
    PyCodeObject *co = f->f_code;

    if (co->co_flags & (CO_GENERATOR | CO_COROUTINE | CO_ASYNC_GENERATOR)) {
        return;
    }

    char *bytecode = NULL;
    Py_ssize_t bytecode_len = -1;
    if (-1 == PyBytes_AsStringAndSize(co->co_code, &bytecode, &bytecode_len)) {
        return;
    }

    // Initialize dynasm for one section.
    dasm_State *d;
    dasm_init(&d, 1);
    dasm_State **Dst = &d;

    |.if X64
    |.arch x64
    |.else
    |.arch x86
    |.endif

    // We'll use a callee-save register for stack-top.  Eventually, it will be
    // worthwhile to think about eliding stack operations, but for simplicity
    // we'll just do a wholesale adaptation of ceval to begin with.
    |.define reg_stack_top, r12

    |.define reg_frame, r13

    |.type PYFRAME, PyFrameObject
    |.type PYCODE, PyCodeObject
    |.type PYTHREADSTATE, PyThreadState
    |.type PYOBJECT, PyObject
    |.type PYRUNTIMESTATE, _PyRuntimeState
    |.type GILSTATE, (struct _gilstate_runtime_state)

    |.section code

    dasm_init(&d, DASM_MAXSECTION);

    |.actionlist py_actions
    dasm_setup(&d, py_actions);

    // Function prologue --- preserve any callee-save registers we clobber.
    | push r12
    | push r13
    | push rbp
    | mov rbp, rsp

    // Frame arrives in rdi
    | mov reg_frame, rdi

    // throwflag arrives in rsi

    // SysV ABI calling order
    //
    // args: rdi, rsi, rdx, rcx, r8, r9
    //
    // ret: rax (64-bit), rax/rdx (128-bit)

    // Record this frame in the current thread state
    //
    // _Py_atomic_load_relaxed(_PyRuntime.gilstate.tstate_current)
    | mov64 rax, ((uintptr_t)&(_PyRuntime.gilstate.tstate_current))
    | mov aword PYTHREADSTATE:rax->frame, reg_frame

    // Null out the frame's copy of the stack top
    | mov reg_stack_top, PYFRAME:reg_frame->f_stacktop
    | mov aword PYFRAME:reg_frame->f_stacktop, 0

    // Mark the frame as executing
    | mov byte PYFRAME:reg_frame->f_executing, 1

    // TODO: call Py_EnterRecursiveCall, returning if it fails.  (It's a macro,
    // not a function).

    _Py_CODEUNIT *bytecode_src = (_Py_CODEUNIT*) bytecode;
    _Py_CODEUNIT *bytecode_point = bytecode_src;
    _Py_CODEUNIT *bytecode_lim = (_Py_CODEUNIT*) bytecode + bytecode_len / sizeof(_Py_CODEUNIT);
    while(bytecode_point != bytecode_lim) {
        _Py_CODEUNIT instr = *bytecode_point;
        int opcode = _Py_OPCODE(instr);
        int oparg = _Py_OPARG(instr);
        switch(opcode) {
        case LOAD_CONST: {
            | mov rdi, PYFRAME:reg_frame->f_code
            | mov rdi, PYCODE:rdi->co_consts
            | mov rsi, oparg
            | mov64 rax, ((uintptr_t)((void*)&PyTuple_GetItem))
            | call rax

            | add aword PYOBJECT:rax->ob_refcnt, 1

            | mov [reg_stack_top], rax
            | add reg_stack_top, 8
            break;
        }
        case RETURN_VALUE: {
            | sub reg_stack_top, 8
            | mov rax, [reg_stack_top]
            goto emit_return_or_yield;
        }
        default: {
            // Unsupported instruction.  Not an error, but we need to bail out of compilation.
            /* fprintf(stderr, */
            /*         "Unrecognized instruction %d.  Bailing out of JIT compilation at %d\n", */
            /*         opcode, */
            /*         PyFrame_GetLineNumber(f)); */
            goto cleanup_dasm;
        }
        }

        ++bytecode_point;
    }

  emit_exception_unwind:
    // TODO: Generate code corresponding to the exception_unwind section in ceval
  emit_return_or_yield:
  emit_exit_eval_frame:

    // TODO: Call Py_LeaveRecursiveCall (It's a macro)

    // Now the return value is in rax

    | mov byte PYFRAME:reg_frame->f_executing, 0

    | mov64 rbx, ((uintptr_t)&(_PyRuntime.gilstate.tstate_current))
    | mov aword PYTHREADSTATE:rbx->frame, reg_frame

    | mov rdi, PYFRAME:reg_frame->f_code
    | mov rsi, rax
    | mov rdx, 0
    | mov64 rax, ((uintptr_t)_Py_CheckFunctionResult)
    | call rax

    | mov rsp, rbp
    | pop rbp
    | pop r13
    | pop r12
    | ret

    fprintf(stderr, "Linking and encoding\n");
    link_and_encode(&d, &(co->co_basic_jitcode), &(co->co_basic_jitcode_len));

    // Py_INCREF looks like
    //
    // obj->ob_refcnt = obj->ob_refcnt + 1;

    // Py_DECREF looks like
    //
    // obj->ob_refcnt = obj->ob_refcnt - 1;
    // if(obj->ob_refcnt == 0) {
    //     _Py_Dealloc(obj);
    // }

    // _Py_Dealloc looks like
    //
    // Py_TYPE(obj)->tp_dealloc(obj);

    // Py_Type looks like
    //
    // obj->ob_type

    // PyThreadState *tstate = PyThreadState_GET();
    // tstate->frame = f;
    // stack_pointer = f->f_stacktop;
    // f->f_stacktop = NULL;
    // f->f_executing = 1;
    //
    // if(Py_EnterRecursiveCall("")) {
    //   return NULL;
    // }
    //
    // {
    //   PyObject *value = GETITEM(consts, oparg);
    //   Py_INCREF(value);
    //   PUSH(value);
    //   FAST_DISPATCH();
    // }
    // {
    //   retval = POP();
    //   assert(f->f_iblock == 0);
    //   goto return_or_yield;
    // }
    // return_or_yield:
    // {
    //   Py_LeaveRecursiveCall()
    //   f->f_executing = 0;
    //   tstate->frame = f->f_back;
    //   return _Py_CheckFunctionResult(NULL, retval, "PyEval_EvalFrameEx"
    // }

  cleanup_dasm:
    dasm_free(&d);
}

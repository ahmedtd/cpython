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

    // Bail out on any coroutine stuff.  The generated code fails to run, even
    // if it doesn't contain any coroutine-specific instructions.
    if (co->co_flags & (CO_GENERATOR | CO_COROUTINE | CO_ASYNC_GENERATOR)) {
        return;
    }

    // Retrieve bytecode.
    char *bytecode = NULL;
    Py_ssize_t bytecode_len = -1;
    if (-1 == PyBytes_AsStringAndSize(co->co_code, &bytecode, &bytecode_len)) {
        return;
    }

    // Initialize dynasm for one section.
    dasm_State *d;
    dasm_init(&d, 1);
    dasm_State **Dst = &d;

    |.arch x64

    // We'll use a callee-save register for stack-top.  Eventually, it will be
    // worthwhile to think about eliding stack operations, but for simplicity
    // we'll just do a wholesale adaptation of ceval to begin with.
    |.define reg_stack_top, r12
    |.define reg_frame, r13
    |.define reg_throwflag, r14

    |.type PYFRAME, PyFrameObject
    |.type PYCODE, PyCodeObject
    |.type PYTHREADSTATE, PyThreadState
    |.type PYOBJECT, PyObject
    |.type PYTYPE, PyTypeObject
    |.type PYRUNTIMESTATE, _PyRuntimeState
    |.type GILSTATE, (struct _gilstate_runtime_state)

    /* Takes the address of a PyObject in rdi, and a caller-specified temp
       register.

       Clobbers rdi, tmp_reg
    */
    |.macro Py_XDECREF, tmp_reg
    | test rdi, rdi
    | jz >1
    |
    | mov tmp_reg, PYOBJECT:rdi->ob_refcnt
    | sub aword [tmp_reg], 1
    | ja >1
    |
    | mov tmp_reg, PYOBJECT:rdi->ob_type
    | mov tmp_reg, PYTYPE:tmp_reg->tp_dealloc
    | call tmp_reg
    |
    |1:
    |.endmacro

    |.section code

    dasm_init(&d, DASM_MAXSECTION);

    |.globals lbl_
    void* labels[lbl__MAX];
    dasm_setupglobal(&d, labels, lbl__MAX);

    |.actionlist py_actions
    dasm_setup(&d, py_actions);

    unsigned int next_pc = 0;
    unsigned int num_pc = 8;
    dasm_growpc(&d, num_pc);

    |->jit_entry:

    // Function prologue --- preserve any callee-save registers we clobber.
    | push r12
    | push r13
    | push reg_throwflag
    | push rbp
    | mov rbp, rsp

    // Frame arrives in rdi
    | mov reg_frame, rdi

    // throwflag arrives in rsi
    | mov reg_throwflag, rsi

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

    // Support for generator.throw()
    | test reg_throwflag, reg_throwflag
    | jnz ->error

    _Py_CODEUNIT *bytecode_src = (_Py_CODEUNIT*) bytecode;
    _Py_CODEUNIT *bytecode_point = bytecode_src;
    _Py_CODEUNIT *bytecode_lim = (_Py_CODEUNIT*) bytecode + bytecode_len / sizeof(_Py_CODEUNIT);
    while(bytecode_point != bytecode_lim) {
        _Py_CODEUNIT instr = *bytecode_point;
        int opcode = _Py_OPCODE(instr);
        int oparg = _Py_OPARG(instr);

        switch(opcode) {
        case NOP: {
            break;
        }
        case LOAD_FAST: {

            // f_localsplus is a variable-sized array at the end of the frame
            // object, so it's not correct to use dynasm's built-in deref
            // support.
            int local_offset = offsetof(PyFrameObject, f_localsplus) + 8 * oparg;
            | mov rdi, [reg_frame+local_offset]

            // TODO:
            // if (value == NULL) {
            //     format_exc_check_arg(PyExc_UnboundLocalError,
            //                          UNBOUNDLOCAL_ERROR_MSG,
            //                          PyTuple_GetItem(co->co_varnames, oparg));
            //     goto error;
            // }

            | add aword PYOBJECT:rdi->ob_refcnt, 1

            | mov [reg_stack_top], rdi
            | add reg_stack_top, 8

            break;
        }
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
        case STORE_FAST: {
            | sub reg_stack_top, 8
            | mov rdx, [reg_stack_top]

            int local_offset = offsetof(PyFrameObject, f_localsplus) + 8 * oparg;
            | mov rdi, [reg_frame+local_offset]
            | mov [reg_frame+local_offset], rdx

            | Py_XDECREF rsi

            break;
        }
        case RETURN_VALUE: {
            | sub reg_stack_top, 8
            | mov rax, [reg_stack_top]
            | jmp ->return_or_yield

            break;
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

    // TODO: Emit a guard so that execution can't walk off the end of the
    // generated instructions.

    |->error:

    // TODO: Assemble
    //
    // if (!PyErr_Occurred()) {
    //     PyErr_SetString(PyExc_SystemError,
    //                     "error return without exception set");
    // }

    // TODO: Assemble PyTraceBack_Here(f)

    // TODO: Assemble
    //
    // if (tstate->c_tracefunc != NULL)
    //     call_exc_trace(tstate->c_tracefunc,
    //                    tstate->c_traceobj,
    //                    tstate,
    //                    f);

    |->exception_unwind:

    // TODO: Emit exception unwind code.  We don't support any try opcodes yet,
    // so it's fine not to support it.

    // Hmmm... error and exception_unwind are in the main loop in ceval.c, since
    // they can `continue` back to processing the next instruction, after doing
    // the proper try block.
    //
    // I think I'm going to need to emit pc labels for each bytecode
    // instruction...

    // TODO: emit tracing code


    // TODO: Call Py_LeaveRecursiveCall (It's a macro)

    // Now the return value is in rax

    |->return_or_yield:
    |
    | mov byte PYFRAME:reg_frame->f_executing, 0

    | mov64 rbx, ((uintptr_t)&(_PyRuntime.gilstate.tstate_current))
    | mov rdi, PYFRAME:reg_frame->f_back
    | mov aword PYTHREADSTATE:rbx->frame, rdi

    | mov rdi, PYFRAME:reg_frame->f_code
    | mov rsi, rax
    | mov rdx, 0
    | mov64 rax, ((uintptr_t)_Py_CheckFunctionResult)
    | call rax

    | mov rsp, rbp
    | pop rbp
    | pop reg_throwflag
    | pop r13
    | pop r12
    | ret

    link_and_encode(&d, &(co->co_basic_jitcode), &(co->co_basic_jitcode_len));
    co->co_basic_jitcode_entry = labels[lbl_jit_entry];

  cleanup_dasm:
    dasm_free(&d);
}

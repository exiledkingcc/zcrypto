#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "zcrypto/sm3.h"
#include "zcrypto/sm4.h"

typedef struct {
    PyObject_HEAD
    sm3_ctx_t ctx;
} SM3Object;

static int SM3_init(SM3Object *self, PyObject *args, PyObject *kwargs) {
    if (PyTuple_Size(args) != 0 || kwargs != NULL) {
        PyErr_SetString(PyExc_ValueError, "no args/kwargs");
        return -1;
    }
    sm3_init(&self->ctx);
    return 0;
}

static void SM3_dealloc(SM3Object *self) {
    memset(&self->ctx, 0, sizeof(sm3_ctx_t));
}

static PyObject *SM3_update(SM3Object *self, PyObject *data) {
    if (!PyBytes_Check(data)) {
        PyErr_SetString(PyExc_ValueError, "data MUST be bytes");
        return NULL;
    }
    Py_ssize_t len = PyBytes_Size(data);
    char *dd = PyBytes_AsString(data);
    sm3_update(&self->ctx, (const uint8_t *)dd, len);
    return Py_None;
}

static PyObject *SM3_digest(SM3Object *self) {
    uint8_t digest[32] = {0};
    sm3_digest(&self->ctx, digest);
    return PyBytes_FromStringAndSize((const char *)digest, 32);
}

static PyObject *SM3_hexdigest(SM3Object *self) {
    uint8_t digest[64] = {0};
    sm3_hexdigest(&self->ctx, digest);
    return PyUnicode_FromStringAndSize((const char *)digest, 64);
}

static PyMethodDef SM3_methods[] = {
    {
        "update",
        (PyCFunction)SM3_update,
        METH_O,
        "feed data"
    },
    {
        "digest",
        (PyCFunction)SM3_digest,
        METH_NOARGS,
        "digest"
    },
    {
        "hexdigest",
        (PyCFunction)SM3_hexdigest,
        METH_NOARGS,
        "hexdigest"
    },
    {NULL}
};

static PyTypeObject SM3Type = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "zcrypto.SM3",
    .tp_doc = "sm3_ctx_t",
    .tp_basicsize = sizeof(SM3Object),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc)SM3_init,
    .tp_dealloc = (destructor)SM3_dealloc,
    .tp_methods = SM3_methods,
};

typedef struct {
    PyObject_HEAD
    sm4_ctx_t ctx;
} SM4Object;

static int SM4_init(SM4Object *self, PyObject *args, PyObject *kwargs) {
    static char *kwlist[] = {"", "", "iv", NULL};
    PyObject *key = NULL;
    PyObject *iv = NULL;
    int mode = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "Si|S", kwlist, &key, &mode, &iv)) {
        PyErr_SetString(PyExc_ValueError, "(key:bytes, mode:int, iv:bytes=?) is required");
        return -1;
    }
    if (PyBytes_Size(key) != 16) {
        PyErr_SetString(PyExc_ValueError, "len(key) == 16 is required");
        return -1;
    }
    if (mode < SM4_MIN_MODE || mode > SM4_MAX_MODE) {
        PyErr_Format(PyExc_ValueError, "mode MUST in %d...%d", SM4_MIN_MODE, SM4_MAX_MODE);
        return -1;
    }
    if (mode == SM4_ECB_MODE && iv != NULL) {
        PyErr_SetString(PyExc_ValueError, "ECB_MODE requires no iv");
        return -1;
    }
    if (mode != SM4_ECB_MODE && iv == NULL) {
        PyErr_SetString(PyExc_ValueError, "iv is required");
        return -1;
    }
    uint8_t *ivdata = NULL;
    if (iv != NULL) {
        if (PyBytes_Size(iv) != 16) {
            PyErr_SetString(PyExc_ValueError, "len(iv) == 16 is required");
            return -1;
        }
        ivdata = (uint8_t*)PyBytes_AsString(iv);
    }
    uint8_t *keydata = (uint8_t*)PyBytes_AsString(key);
    int r = sm4_init(&self->ctx, mode, keydata, ivdata);
    if (r != 0) {
        PyErr_SetString(PyExc_Exception, "sm4_init failed");
        return -1;
    }
    return 0;
}

static void SM4_dealloc(SM4Object *self) {
    memset(&self->ctx, 0, sizeof(sm4_ctx_t));
}

static PyObject *SM4_encrypt(SM4Object *self, PyObject *data) {
    if (!PyBytes_Check(data)) {
        PyErr_SetString(PyExc_ValueError, "data MUST be bytes");
        return NULL;
    }
    Py_ssize_t len = PyBytes_Size(data);
    if (PyBytes_Size(data) % 16 != 0) {
        PyErr_SetString(PyExc_ValueError, "len(data) == 16*N is required");
        return NULL;
    }
    uint8_t *dd = (uint8_t*)PyBytes_AsString(data);
    uint8_t *cc = (uint8_t*)malloc(len);
    int r = sm4_encrypt(&self->ctx, len, dd, cc);
    if (r != 0) {
        free(cc);
        PyErr_SetString(PyExc_Exception, "sm4_encrypt failed");
        return NULL;
    }
    PyObject *out = PyBytes_FromStringAndSize((const char *)cc, len);
    free(cc);
    return out;
}

static PyObject *SM4_decrypt(SM4Object *self, PyObject *data) {
    if (!PyBytes_Check(data)) {
        PyErr_SetString(PyExc_ValueError, "data MUST be bytes");
        return NULL;
    }
    Py_ssize_t len = PyBytes_Size(data);
    if (PyBytes_Size(data) % 16 != 0) {
        PyErr_SetString(PyExc_ValueError, "len(data) == 16*N is required");
        return NULL;
    }
    uint8_t *dd = (uint8_t*)PyBytes_AsString(data);
    uint8_t *cc = (uint8_t*)malloc(len);
    int r = sm4_decrypt(&self->ctx, len, dd, cc);
    if (r != 0) {
        free(cc);
        PyErr_SetString(PyExc_Exception, "sm4_decrypt failed");
        return NULL;
    }
    PyObject *out = PyBytes_FromStringAndSize((const char *)cc, len);
    free(cc);
    return out;
}

static PyMethodDef SM4_methods[] = {
    {
        "encrypt",
        (PyCFunction)SM4_encrypt,
        METH_O,
        "encrypt"
    },
    {
        "decrypt",
        (PyCFunction)SM4_decrypt,
        METH_O,
        "decrypt"
    },
    {NULL}
};

static PyTypeObject SM4Type = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "zcrypto.SM4",
    .tp_doc = "sm4_ctx_t",
    .tp_basicsize = sizeof(SM4Object),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc)SM4_init,
    .tp_dealloc = (destructor)SM4_dealloc,
    .tp_methods = SM4_methods,
};

PyObject *sm3(PyObject *Py_UNUSED(self), PyObject *data) {
    if (!PyBytes_Check(data)) {
        PyErr_SetString(PyExc_ValueError, "data MUST be bytes");
        return NULL;
    }
    Py_ssize_t len = PyBytes_Size(data);
    char *dd = PyBytes_AsString(data);
    uint8_t digest[32] = {0};
    sm3_ctx_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, (const uint8_t *)dd, len);
    sm3_digest(&ctx, digest);
    return PyBytes_FromStringAndSize((const char *)digest, 32);
}

PyMethodDef zcrypto_funcs[] = {
    {"sm3", sm3, METH_O, "sm3"},
    {NULL}
};

PyModuleDef zcrypto_mod = {
    PyModuleDef_HEAD_INIT,
    "zcrypto", "zcrypto python interface",
    -1,
    zcrypto_funcs,
    NULL,
    NULL,
    NULL,
    NULL,
};


#define _add_type(MOD, TYPE, NAME) \
if (PyType_Ready(&TYPE) < 0) { \
    return NULL; \
} \
Py_INCREF(&TYPE); \
if (PyModule_AddObject(MOD, NAME, (PyObject*)&TYPE) < 0) { \
    Py_DECREF(&TYPE); \
    Py_DECREF(MOD); \
    return NULL; \
}

PyMODINIT_FUNC PyInit_zcrypto(void) {
    PyObject *mod = PyModule_Create(&zcrypto_mod);
    if (mod == NULL) {
        return NULL;
    }

    PyModule_AddIntConstant(mod, "SM4_ECB", SM4_ECB_MODE);
    PyModule_AddIntConstant(mod, "SM4_CBC", SM4_CBC_MODE);
    PyModule_AddIntConstant(mod, "SM4_CFB", SM4_CFB_MODE);
    PyModule_AddIntConstant(mod, "SM4_OFB", SM4_OFB_MODE);

    _add_type(mod, SM3Type, "SM3")
    _add_type(mod, SM4Type, "SM4")

    return mod;
}

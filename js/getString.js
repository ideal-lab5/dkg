let cachedTextEncoder = new lTextEncoder('utf-8');

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc, wasm_memory_buffer) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length);
        getUint8Memory0(wasm_memory_buffer).subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len);

    const mem = getUint8Memory0(wasm_memory_buffer);

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3);
        const view = getUint8Memory0(wasm_memory_buffer).subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}


/**
* @param {&JsValue} wasm: wasm object
* @param {string} fn_name: function's name to call in the wasm object
* @param {string} name: param to give to fn_name
* @returns {string}
*/
export function getString(wasm, fn_name, name) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc, wasm.memory.buffer);
        const len0 = WASM_VECTOR_LEN;
        //wasm.hello(retptr, ptr0, len0);
        wasm[fn_name](retptr, ptr0, len0);
        var r0 = getInt32Memory0(wasm.memory.buffer)[retptr / 4 + 0];
        var r1 = getInt32Memory0(wasm.memory.buffer)[retptr / 4 + 1];
        return getStringFromWasm(r0, r1, wasm.memory.buffer);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_free(r0, r1);
    }
}
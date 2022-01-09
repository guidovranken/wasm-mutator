use std::slice;
use std::ptr;
use wasmparser::WasmFeatures;

extern "C" {
    pub fn LLVMFuzzerMutate(data: *mut u8, size: usize, max_size: usize) -> usize;
}

#[no_mangle]
pub extern "C" fn LLVMFuzzerCustomMutator(data: *mut u8, size: libc::size_t, max_size: libc::size_t, seed: u32) -> usize {
    if (seed % 10) == 0 {
        unsafe {
            return LLVMFuzzerMutate(data, size, max_size);
        }
    }
    let wasm = unsafe { slice::from_raw_parts(data, size) };
    let features = WasmFeatures::default();
    let mut validator = wasmparser::Validator::new();
    validator.wasm_features(features);
    let validation_result = validator.validate_all(&wasm);

    let wasm = if validation_result.is_ok() {
        wasm.to_vec()
    } else {
        let (w, _) = match wasm_tools_fuzz::generate_valid_module(&wasm, |config, u| {
            config.module_linking_enabled = false;
            config.exceptions_enabled = false;
            config.simd_enabled = false;
            config.reference_types_enabled = false;
            config.memory64_enabled = false;
            config.max_memories = 1;
            Ok(())
        }) {
            Ok(m) => m,
            Err(_e) => {
                unsafe {
                    return LLVMFuzzerMutate(data, size, max_size);
                }
            }
        };
        w
    };

    let mut mutator = wasm_mutate::WasmMutate::default();
    let xwasm = wasm.to_vec();
    let mutated_wasm = mutator
        .seed(seed.into())
        .fuel(1000)
        .preserve_semantics(true)
        .run(&xwasm);

    let mut iterator = match mutated_wasm {
        Ok(iterator) => iterator,
        Err(_e) => {
            unsafe {
                return LLVMFuzzerMutate(data, size, max_size);
            }
        }
    };

    let mutated_wasm = match iterator.next() {
        Some(w) => {
            w.unwrap()
        }
        None => wasm,
    };

    let newsize = mutated_wasm.len();
    if newsize > max_size {
            unsafe {
                return LLVMFuzzerMutate(data, size, max_size);
            }
    }

    unsafe {
        ptr::copy_nonoverlapping(mutated_wasm.as_ptr(), data, newsize);
    }

    return newsize;
}

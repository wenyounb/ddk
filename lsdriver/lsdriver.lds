SECTIONS {
	__patchable_function_entries : { *(__patchable_function_entries) }
	.text : {
		_match_physical_touchscreen.cfi_jt = . + 0x1f30;
		compare_ull.cfi_jt = . + 0x1f38;
		init_module.cfi_jt = . + 0x1f40;
		ConnectThreadFunction.cfi_jt = . + 0x1f48;
		DispatchThreadFunction.cfi_jt = . + 0x1f50;
		cleanup_module.cfi_jt = . + 0x1f58;
	}
}

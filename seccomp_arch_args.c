void go2libc_seccomp_get(const ucontext_t *uc_in, struct seccomp_data *data_out) {
	data_out->nr = uc_in->uc_mcontext.gregs[REG_RAX];
	data_out->args[0] = uc_in->uc_mcontext.gregs[REG_RDI];
	data_out->args[1] = uc_in->uc_mcontext.gregs[REG_RSI];
	data_out->args[2] = uc_in->uc_mcontext.gregs[REG_RDX];
	data_out->args[3] = uc_in->uc_mcontext.gregs[REG_R10];
	data_out->args[4] = uc_in->uc_mcontext.gregs[REG_R8];
	data_out->args[5] = uc_in->uc_mcontext.gregs[REG_R9];
}
void go2libc_seccomp_ret(long retval, ucontext_t *uc_out) {
	uc_out->uc_mcontext.gregs[REG_RAX] = retval == -1 ? (-(uint64_t)errno) : retval;
}

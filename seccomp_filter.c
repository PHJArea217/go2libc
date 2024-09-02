static void sigsys_handler(int signo, siginfo_t *si, void *uc_void) {
	if (signo != SIGSYS) return;
	if (si->si_code != 1) return; /*SYS_SECCOMP*/
	if (uc_void == NULL) return;
	
	ucontext_t *uc = uc_void;
	struct seccomp_data syscall_args = {};
	go2libc_seccomp_get(&syscall_args, uc);
	int saved_errno = errno;
	long retval = -1;
	switch (syscall_args.nr) {
		case __NR_socket:
			retval = socket(syscall_args.args[0], syscall_args.args[1], syscall_args.args[2]);
			break;
		case __NR_connect:
			retval = connect(syscall_args.args[0], (struct sockaddr *)syscall_args.args[1], syscall_args.args[2]);
			break;
		case __NR_bind:
			retval = bind(syscall_args.args[0], (struct sockaddr *)syscall_args.args[1], syscall_args.args[2]);
			break;
		case __NR_listen:
			retval = listen(syscall_args.args[0], syscall_args.args[1]);
			break;
		case __NR_accept:
			retval = accept(syscall_args.args[0], (struct sockaddr *)syscall_args.args[1], syscall_args.args[2]);
			break;
		case __NR_accept4:
			retval = accept4(syscall_args.args[0], (struct sockaddr *)syscall_args.args[1], syscall_args.args[2], syscall_args.args[3]);
			break;
		case __NR_getsockname:
			retval = getsockname(syscall_args.args[0], (struct sockaddr *)syscall_args.args[1], syscall_args.args[2]);
			break;
		case __NR_getpeername:
			retval = getpeername(syscall_args.args[0], (struct sockaddr *)syscall_args.args[1], syscall_args.args[2]);
			break;
		case __NR_openat:
			retval = openat(syscall_args.args[0], (char *)syscall_args.args[1], syscall_args.args[2], syscall_args.args[3]);
			break;
		default:
			abort();
			break;
	}
	go2libc_seccomp_ret(uc, retval);
	errno = saved_errno;
}
int go2libc_install_filter(struct go2libc_params *params) {
	struct sigaction sigsys_action = {.sa_sigaction = sigsys_handler, .sa_flags = SA_SIGINFO|SA_ONSTACK|SA_RESTART};
	sigfillset(&sigsys_action.sa_mask);
	if (sigaction(SIGSYS, &sigsys_action, NULL)) {
		return -1;
	}
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	uint32_t app_low_lo = params->app_low & 0xffffffff;
	uint32_t app_low_hi = params->app_low >> 32;
	uint32_t app_high_lo = params->app_high & 0xffffffff;
	uint32_t app_high_hi = params->app_high >> 32;
	
	struct sock_filter filter[] = {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 12), // instruction_pointer[63:32]
#else
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 8),
#endif
		BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, app_low_hi, 0, 4), // are we within app?
		BPF_JUMP(BPF_JMP|BPF_JGT|BPF_K, app_high_hi, 3, 0),
#if __BYTE_ORDER == __LITTLE_ENDIAN
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 8), // instruction_pointer[31:0]
#else
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 12),
#endif
		BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, app_low_lo, 0, 1),
		BPF_JUMP(BPF_JMP|BPF_JGT|BPF_K, app_high_hi, 0, 1),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
		// TODO: check AUDIT_ARCH_*
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 0), // syscall nr
		// TODO: sendto/sendmsg MSG_FASTOPEN -> SECCOMP_RET_ERRNO|EPIPE
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_socket, 10, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_connect, 9, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_bind, 8, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_listen, 7, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_accept, 6, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_accept4, 5, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getsockname, 4, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getpeername, 3, 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),//BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_sendto, 3, 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),//BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_sendmsg, 2, 0),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP)
	};
	struct sock_fprog fp = {.len = sizeof(filter)/sizeof(filter[0]), .filter = filter};
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fp)) {
		return -1;
	}
	return 0;
}

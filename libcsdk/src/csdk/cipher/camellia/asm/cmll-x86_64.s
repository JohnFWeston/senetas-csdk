.text	

.globl	_x86_64_Camellia_ctr32_encrypt_blocks
.type	_x86_64_Camellia_ctr32_encrypt_blocks,@function
.align	16
_x86_64_Camellia_ctr32_encrypt_blocks:
.cfi_startproc	
	# args: rdi=in, rsi=out, rdx=blocks, rcx=key, r8=keybits, r9=ivec
	# return if no blocks
	testq	%rdx,%rdx
	jz	.Lctr_return

	# save callee-saved regs we will use to hold persistent pointers/counters
	pushq	%rbp
	pushq	%rbx
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15

	# persist inputs across calls in callee-saved regs
	movq	%rdi,%r12		# r12 = in ptr
	movq	%rsi,%r13		# r13 = out ptr
	movq	%rcx,%rbx		# rbx = key table
	movq	%rdx,%r15		# r15 = blocks remaining
	movl	%r8d,%ebp		# ebp = key bits
	movq	%r9,%r14		# r14 = ivec

	# allocate 24-byte scratch for keystream and maintain 16-byte alignment at call sites
	subq	$24,%rsp

.Lctr_loop:
	# keystream = E_K(ivec)
	movl	%ebp,%edi		# keyBitLength
	movq	%r14,%rsi		# in  = ivec
	movq	%rbx,%rdx		# key table
	leaq	(%rsp),%rcx		# out = keystream buffer
	call	Camellia_EncryptBlock

	# XOR keystream with plaintext -> ciphertext
	movdqu	(%r12),%xmm0
	movdqu	(%rsp),%xmm1
	pxor	%xmm1,%xmm0
	movdqu	%xmm0,(%r13)

	# advance plaintext/ciphertext pointers
	addq	$16,%r12
	addq	$16,%r13

	# increment 32-bit big-endian counter at ivec[12..15]
	movl	12(%r14),%ecx
	bswapl	%ecx
	addl	$1,%ecx
	bswapl	%ecx
	movl	%ecx,12(%r14)

	decq	%r15
	jnz	.Lctr_loop

	addq	$24,%rsp
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbx
	popq	%rbp
.Lctr_return:
	ret
.cfi_endproc	
.size	_x86_64_Camellia_ctr32_encrypt_blocks,.-_x86_64_Camellia_ctr32_encrypt_blocks

#
# This file contains highly optimized AES (Advanced Encryption Standard) functions
# for the x86-64 architecture, utilizing the AES-NI (Advanced Encryption Standard
# New Instructions) instruction set for hardware acceleration.
#

.text                                       # Start of the text (code) section

# Function: snts_aesni_encrypt
# Encrypts a single 16-byte block of data using AES.
# Arguments:
#   RDI: Pointer to the 16-byte plaintext input.
#   RSI: Pointer to the 16-byte buffer for the ciphertext output.
#   RDX: Pointer to the AES key schedule.
.globl  snts_aesni_encrypt                          # Make the function snts_aesni_encrypt visible to the linker
.type   snts_aesni_encrypt,@function                # Define snts_aesni_encrypt as a function
.align  16                                          # Align the function to a 16-byte boundary for performance
snts_aesni_encrypt:                                 # Start of the function snts_aesni_encrypt
.cfi_startproc                                      # Call Frame Information: marks the start of the function
.byte   243,15,30,250                               # endbr64 instruction for CET security feature
	movups	(%rdi),%xmm2			# Load 16 bytes of plaintext from address in RDI into XMM2
	movl	240(%rdx),%eax			# Load the number of rounds from the key schedule (RDX+240) into EAX
	movups	(%rdx),%xmm0			# Load the first 16-byte round key from RDX into XMM0
	movups	16(%rdx),%xmm1			# Load the second 16-byte round key from RDX+16 into XMM1
	leaq	32(%rdx),%rdx			# Advance the key schedule pointer (RDX) by 32 bytes
	xorps	%xmm0,%xmm2			# Perform the initial AddRoundKey: XOR plaintext with the first round key
.Loop_enc1_1:					# Label for the main encryption loop
.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2 : Perform one round of AES encryption
	decl	%eax				# Decrement the round counter in EAX
	movups	(%rdx),%xmm1			# Load the next round key into XMM1
	leaq	16(%rdx),%rdx			# Advance the key schedule pointer by 16 bytes
	jnz	.Loop_enc1_1			# Jump back to the loop if rounds are left (EAX is not zero)
.byte	102,15,56,221,209			# aesenclast %xmm1, %xmm2 : Perform the final round of AES encryption
	pxor	%xmm0,%xmm0			# Clear XMM0 register to prevent data leakage
	pxor	%xmm1,%xmm1			# Clear XMM1 register to prevent data leakage
	movups	%xmm2,(%rsi)			# Store the resulting 16-byte ciphertext from XMM2 to address in RSI
	pxor	%xmm2,%xmm2			# Clear XMM2 register to prevent data leakage
	.byte	0xf3,0xc3				# rep ret: Return from the function
.cfi_endproc					# Call Frame Information: marks the end of the function
.size	snts_aesni_encrypt,.-snts_aesni_encrypt	# Set the size of the function symbol for the linker

# Function: snts_aesni_decrypt
# Decrypts a single 16-byte block of data using AES.
# Arguments:
#   RDI: Pointer to the 16-byte ciphertext input.
#   RSI: Pointer to the 16-byte buffer for the plaintext output.
#   RDX: Pointer to the AES decryption key schedule.
.globl	snts_aesni_decrypt			# Make the function snts_aesni_decrypt visible to the linker
.type	snts_aesni_decrypt,@function		# Define snts_aesni_decrypt as a function
.align	16					# Align the function to a 16-byte boundary
snts_aesni_decrypt:				# Start of the function snts_aesni_decrypt
.cfi_startproc					# CFI: marks the start of the function
.byte	243,15,30,250				# endbr64 instruction for CET security
	movups	(%rdi),%xmm2			# Load 16 bytes of ciphertext from address in RDI into XMM2
	movl	240(%rdx),%eax			# Load the number of rounds from the key schedule (RDX+240) into EAX
	movups	(%rdx),%xmm0			# Load the first 16-byte round key from RDX into XMM0
	movups	16(%rdx),%xmm1			# Load the second 16-byte round key from RDX+16 into XMM1
	leaq	32(%rdx),%rdx			# Advance the key schedule pointer by 32 bytes
	xorps	%xmm0,%xmm2			# Perform the initial AddRoundKey: XOR ciphertext with the first round key
.Loop_dec1_2:					# Label for the main decryption loop
.byte	102,15,56,222,209			# aesdec %xmm1, %xmm2 : Perform one round of AES decryption
	decl	%eax				# Decrement the round counter in EAX
	movups	(%rdx),%xmm1			# Load the next round key into XMM1
	leaq	16(%rdx),%rdx			# Advance the key schedule pointer by 16 bytes
	jnz	.Loop_dec1_2			# Jump back to the loop if rounds are left
.byte	102,15,56,223,209			# aesdeclast %xmm1, %xmm2 : Perform the final round of AES decryption
	pxor	%xmm0,%xmm0			# Clear XMM0 register
	pxor	%xmm1,%xmm1			# Clear XMM1 register
	movups	%xmm2,(%rsi)			# Store the resulting 16-byte plaintext from XMM2 to address in RSI
	pxor	%xmm2,%xmm2			# Clear XMM2 register
	.byte	0xf3,0xc3				# rep ret: Return from the function
.cfi_endproc					# CFI: marks the end of the function
.size	snts_aesni_decrypt, .-snts_aesni_decrypt	# Set the size of the function symbol

# Internal function: _snts_aesni_encrypt2
# Encrypts 2 blocks of data in parallel.
.type	_snts_aesni_encrypt2,@function		# Define as a function
.align	16					# Align to 16-byte boundary
_snts_aesni_encrypt2:				# Function label
.cfi_startproc					# CFI start
	movups	(%rcx),%xmm0			# Load first round key
	shll	$4,%eax				# Calculate offset for key schedule
	movups	16(%rcx),%xmm1			# Load second round key
	xorps	%xmm0,%xmm2			# AddRoundKey for block 1
	xorps	%xmm0,%xmm3			# AddRoundKey for block 2
	movups	32(%rcx),%xmm0			# Load third round key
	leaq	32(%rcx,%rax,1),%rcx		# Calculate end of key schedule
	negq	%rax				# Negate offset for loop countdown
	addq	$16,%rax				# Adjust offset

.Lenc_loop2:					# Loop for encrypting 2 blocks
.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2
.byte	102,15,56,220,217			# aesenc %xmm1, %xmm3
	movups	(%rcx,%rax,1),%xmm1		# Load next round key
	addq	$32,%rax				# Update offset
.byte	102,15,56,220,208			# aesenc %xmm0, %xmm2
.byte	102,15,56,220,216			# aesenc %xmm0, %xmm3
	movups	-16(%rcx,%rax,1),%xmm0		# Load next round key
	jnz	.Lenc_loop2			# Loop until done

.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2
.byte	102,15,56,220,217			# aesenc %xmm1, %xmm3
.byte	102,15,56,221,208			# aesenclast %xmm0, %xmm2
.byte	102,15,56,221,216			# aesenclast %xmm0, %xmm3
	.byte	0xf3,0xc3				# rep ret: Return
.cfi_endproc					# CFI end
.size	_snts_aesni_encrypt2,.-_snts_aesni_encrypt2	# Set function size

# Internal function: _snts_aesni_decrypt2
# Decrypts 2 blocks of data in parallel.
.type	_snts_aesni_decrypt2,@function		# Define as a function
.align	16					# Align to 16-byte boundary
_snts_aesni_decrypt2:				# Function label
.cfi_startproc					# CFI start
	movups	(%rcx),%xmm0			# Load first round key
	shll	$4,%eax				# Calculate offset for key schedule
	movups	16(%rcx),%xmm1			# Load second round key
	xorps	%xmm0,%xmm2			# AddRoundKey for block 1
	xorps	%xmm0,%xmm3			# AddRoundKey for block 2
	movups	32(%rcx),%xmm0			# Load third round key
	leaq	32(%rcx,%rax,1),%rcx		# Calculate end of key schedule
	negq	%rax				# Negate offset for loop countdown
	addq	$16,%rax				# Adjust offset

.Ldec_loop2:					# Loop for decrypting 2 blocks
.byte	102,15,56,222,209			# aesdec %xmm1, %xmm2
.byte	102,15,56,222,217			# aesdec %xmm1, %xmm3
	movups	(%rcx,%rax,1),%xmm1		# Load next round key
	addq	$32,%rax				# Update offset
.byte	102,15,56,222,208			# aesdec %xmm0, %xmm2
.byte	102,15,56,222,216			# aesdec %xmm0, %xmm3
	movups	-16(%rcx,%rax,1),%xmm0		# Load next round key
	jnz	.Ldec_loop2			# Loop until done

.byte	102,15,56,222,209			# aesdec %xmm1, %xmm2
.byte	102,15,56,222,217			# aesdec %xmm1, %xmm3
.byte	102,15,56,223,208			# aesdeclast %xmm0, %xmm2
.byte	102,15,56,223,216			# aesdeclast %xmm0, %xmm3
	.byte	0xf3,0xc3				# rep ret: Return
.cfi_endproc					# CFI end
.size	_snts_aesni_decrypt2,.-_snts_aesni_decrypt2	# Set function size

# Internal function: _snts_aesni_encrypt3
# Encrypts 3 blocks of data in parallel.
.type	_snts_aesni_encrypt3,@function		# Define as a function
.align	16					# Align to 16-byte boundary
_snts_aesni_encrypt3:				# Function label
.cfi_startproc					# CFI start
	movups	(%rcx),%xmm0			# Load first round key
	shll	$4,%eax				# Calculate offset for key schedule
	movups	16(%rcx),%xmm1			# Load second round key
	xorps	%xmm0,%xmm2			# AddRoundKey for block 1
	xorps	%xmm0,%xmm3			# AddRoundKey for block 2
	xorps	%xmm0,%xmm4			# AddRoundKey for block 3
	movups	32(%rcx),%xmm0			# Load third round key
	leaq	32(%rcx,%rax,1),%rcx		# Calculate end of key schedule
	negq	%rax				# Negate offset for loop countdown
	addq	$16,%rax				# Adjust offset

.Lenc_loop3:					# Loop for encrypting 3 blocks
.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2
.byte	102,15,56,220,217			# aesenc %xmm1, %xmm3
.byte	102,15,56,220,225			# aesenc %xmm1, %xmm4
	movups	(%rcx,%rax,1),%xmm1		# Load next round key
	addq	$32,%rax				# Update offset
.byte	102,15,56,220,208			# aesenc %xmm0, %xmm2
.byte	102,15,56,220,216			# aesenc %xmm0, %xmm3
.byte	102,15,56,220,224			# aesenc %xmm0, %xmm4
	movups	-16(%rcx,%rax,1),%xmm0		# Load next round key
	jnz	.Lenc_loop3			# Loop until done

.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2
.byte	102,15,56,220,217			# aesenc %xmm1, %xmm3
.byte	102,15,56,220,225			# aesenc %xmm1, %xmm4
.byte	102,15,56,221,208			# aesenclast %xmm0, %xmm2
.byte	102,15,56,221,216			# aesenclast %xmm0, %xmm3
.byte	102,15,56,221,224			# aesenclast %xmm0, %xmm4
	.byte	0xf3,0xc3				# rep ret: Return
.cfi_endproc					# CFI end
.size	_snts_aesni_encrypt3,.-_snts_aesni_encrypt3	# Set function size

# Internal function: _snts_aesni_decrypt3
# Decrypts 3 blocks of data in parallel.
.type	_snts_aesni_decrypt3,@function		# Define as a function
.align	16					# Align to 16-byte boundary
_snts_aesni_decrypt3:				# Function label
.cfi_startproc					# CFI start
	movups	(%rcx),%xmm0			# Load first round key
	shll	$4,%eax				# Calculate offset for key schedule
	movups	16(%rcx),%xmm1			# Load second round key
	xorps	%xmm0,%xmm2			# AddRoundKey for block 1
	xorps	%xmm0,%xmm3			# AddRoundKey for block 2
	xorps	%xmm0,%xmm4			# AddRoundKey for block 3
	movups	32(%rcx),%xmm0			# Load third round key
	leaq	32(%rcx,%rax,1),%rcx		# Calculate end of key schedule
	negq	%rax				# Negate offset for loop countdown
	addq	$16,%rax				# Adjust offset

.Ldec_loop3:					# Loop for decrypting 3 blocks
.byte	102,15,56,222,209			# aesdec %xmm1, %xmm2
.byte	102,15,56,222,217			# aesdec %xmm1, %xmm3
.byte	102,15,56,222,225			# aesdec %xmm1, %xmm4
	movups	(%rcx,%rax,1),%xmm1		# Load next round key
	addq	$32,%rax				# Update offset
.byte	102,15,56,222,208			# aesdec %xmm0, %xmm2
.byte	102,15,56,222,216			# aesdec %xmm0, %xmm3
.byte	102,15,56,222,224			# aesdec %xmm0, %xmm4
	movups	-16(%rcx,%rax,1),%xmm0		# Load next round key
	jnz	.Ldec_loop3			# Loop until done

.byte	102,15,56,222,209			# aesdec %xmm1, %xmm2
.byte	102,15,56,222,217			# aesdec %xmm1, %xmm3
.byte	102,15,56,222,225			# aesdec %xmm1, %xmm4
.byte	102,15,56,223,208			# aesdeclast %xmm0, %xmm2
.byte	102,15,56,223,216			# aesdeclast %xmm0, %xmm3
.byte	102,15,56,223,224			# aesdeclast %xmm0, %xmm4
	.byte	0xf3,0xc3				# rep ret: Return
.cfi_endproc					# CFI end
.size	_snts_aesni_decrypt3,.-_snts_aesni_decrypt3	# Set function size

# Internal function: _snts_aesni_encrypt4
# Encrypts 4 blocks of data in parallel.
.type	_snts_aesni_encrypt4,@function		# Define as a function
.align	16					# Align to 16-byte boundary
_snts_aesni_encrypt4:				# Function label
.cfi_startproc					# CFI start
	movups	(%rcx),%xmm0			# Load first round key
	shll	$4,%eax				# Calculate offset for key schedule
	movups	16(%rcx),%xmm1			# Load second round key
	xorps	%xmm0,%xmm2			# AddRoundKey for block 1
	xorps	%xmm0,%xmm3			# AddRoundKey for block 2
	xorps	%xmm0,%xmm4			# AddRoundKey for block 3
	xorps	%xmm0,%xmm5			# AddRoundKey for block 4
	movups	32(%rcx),%xmm0			# Load third round key
	leaq	32(%rcx,%rax,1),%rcx		# Calculate end of key schedule
	negq	%rax				# Negate offset for loop countdown
.byte	0x0f,0x1f,0x00				# NOP for alignment
	addq	$16,%rax				# Adjust offset

.Lenc_loop4:					# Loop for encrypting 4 blocks
.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2
.byte	102,15,56,220,217			# aesenc %xmm1, %xmm3
.byte	102,15,56,220,225			# aesenc %xmm1, %xmm4
.byte	102,15,56,220,233			# aesenc %xmm1, %xmm5
	movups	(%rcx,%rax,1),%xmm1		# Load next round key
	addq	$32,%rax				# Update offset
.byte	102,15,56,220,208			# aesenc %xmm0, %xmm2
.byte	102,15,56,220,216			# aesenc %xmm0, %xmm3
.byte	102,15,56,220,224			# aesenc %xmm0, %xmm4
.byte	102,15,56,220,232			# aesenc %xmm0, %xmm5
	movups	-16(%rcx,%rax,1),%xmm0		# Load next round key
	jnz	.Lenc_loop4			# Loop until done

.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2
.byte	102,15,56,220,217			# aesenc %xmm1, %xmm3
.byte	102,15,56,220,225			# aesenc %xmm1, %xmm4
.byte	102,15,56,220,233			# aesenc %xmm1, %xmm5
.byte	102,15,56,221,208			# aesenclast %xmm0, %xmm2
.byte	102,15,56,221,216			# aesenclast %xmm0, %xmm3
.byte	102,15,56,221,224			# aesenclast %xmm0, %xmm4
.byte	102,15,56,221,232			# aesenclast %xmm0, %xmm5
	.byte	0xf3,0xc3				# rep ret: Return
.cfi_endproc					# CFI end
.size	_snts_aesni_encrypt4,.-_snts_aesni_encrypt4	# Set function size

# Internal function: _snts_aesni_decrypt4
# Decrypts 4 blocks of data in parallel.
.type	_snts_aesni_decrypt4,@function		# Define as a function
.align	16					# Align to 16-byte boundary
_snts_aesni_decrypt4:				# Function label
.cfi_startproc					# CFI start
	movups	(%rcx),%xmm0			# Load first round key
	shll	$4,%eax				# Calculate offset for key schedule
	movups	16(%rcx),%xmm1			# Load second round key
	xorps	%xmm0,%xmm2			# AddRoundKey for block 1
	xorps	%xmm0,%xmm3			# AddRoundKey for block 2
	xorps	%xmm0,%xmm4			# AddRoundKey for block 3
	xorps	%xmm0,%xmm5			# AddRoundKey for block 4
	movups	32(%rcx),%xmm0			# Load third round key
	leaq	32(%rcx,%rax,1),%rcx		# Calculate end of key schedule
	negq	%rax				# Negate offset for loop countdown
.byte	0x0f,0x1f,0x00				# NOP for alignment
	addq	$16,%rax				# Adjust offset

.Ldec_loop4:					# Loop for decrypting 4 blocks
.byte	102,15,56,222,209			# aesdec %xmm1, %xmm2
.byte	102,15,56,222,217			# aesdec %xmm1, %xmm3
.byte	102,15,56,222,225			# aesdec %xmm1, %xmm4
.byte	102,15,56,222,233			# aesdec %xmm1, %xmm5
	movups	(%rcx,%rax,1),%xmm1		# Load next round key
	addq	$32,%rax				# Update offset
.byte	102,15,56,222,208			# aesdec %xmm0, %xmm2
.byte	102,15,56,222,216			# aesdec %xmm0, %xmm3
.byte	102,15,56,222,224			# aesdec %xmm0, %xmm4
.byte	102,15,56,222,232			# aesdec %xmm0, %xmm5
	movups	-16(%rcx,%rax,1),%xmm0		# Load next round key
	jnz	.Ldec_loop4			# Loop until done

.byte	102,15,56,222,209			# aesdec %xmm1, %xmm2
.byte	102,15,56,222,217			# aesdec %xmm1, %xmm3
.byte	102,15,56,222,225			# aesdec %xmm1, %xmm4
.byte	102,15,56,222,233			# aesdec %xmm1, %xmm5
.byte	102,15,56,223,208			# aesdeclast %xmm0, %xmm2
.byte	102,15,56,223,216			# aesdeclast %xmm0, %xmm3
.byte	102,15,56,223,224			# aesdeclast %xmm0, %xmm4
.byte	102,15,56,223,232			# aesdeclast %xmm0, %xmm5
	.byte	0xf3,0xc3				# rep ret: Return
.cfi_endproc					# CFI end
.size	_snts_aesni_decrypt4,.-_snts_aesni_decrypt4	# Set function size

# Internal function: _snts_aesni_encrypt6
# Encrypts 6 blocks of data in parallel.
.type	_snts_aesni_encrypt6,@function		# Define as a function
.align	16					# Align to 16-byte boundary
_snts_aesni_encrypt6:				# Function label
.cfi_startproc					# CFI start
	movups	(%rcx),%xmm0			# Load first round key
	shll	$4,%eax				# Calculate offset for key schedule
	movups	16(%rcx),%xmm1			# Load second round key
	xorps	%xmm0,%xmm2			# AddRoundKey for block 1
	pxor	%xmm0,%xmm3			# AddRoundKey for block 2
	pxor	%xmm0,%xmm4			# AddRoundKey for block 3
.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2
	leaq	32(%rcx,%rax,1),%rcx		# Calculate end of key schedule
	negq	%rax				# Negate offset for loop countdown
.byte	102,15,56,220,217			# aesenc %xmm1, %xmm3
	pxor	%xmm0,%xmm5			# AddRoundKey for block 4
	pxor	%xmm0,%xmm6			# AddRoundKey for block 5
.byte	102,15,56,220,225			# aesenc %xmm1, %xmm4
	pxor	%xmm0,%xmm7			# AddRoundKey for block 6
	movups	(%rcx,%rax,1),%xmm0		# Load next round key
	addq	$16,%rax				# Adjust offset
	jmp	.Lenc_loop6_enter		# Jump to loop entry

.align	16					# Align loop
.Lenc_loop6:					# Loop for encrypting 6 blocks
.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2
.byte	102,15,56,220,217			# aesenc %xmm1, %xmm3
.byte	102,15,56,220,225			# aesenc %xmm1, %xmm4
.Lenc_loop6_enter:				# Loop entry point
.byte	102,15,56,220,233			# aesenc %xmm1, %xmm5
.byte	102,15,56,220,241			# aesenc %xmm1, %xmm6
.byte	102,15,56,220,249			# aesenc %xmm1, %xmm7
	movups	(%rcx,%rax,1),%xmm1		# Load next round key
	addq	$32,%rax				# Update offset
.byte	102,15,56,220,208			# aesenc %xmm0, %xmm2
.byte	102,15,56,220,216			# aesenc %xmm0, %xmm3
.byte	102,15,56,220,224			# aesenc %xmm0, %xmm4
.byte	102,15,56,220,232			# aesenc %xmm0, %xmm5
.byte	102,15,56,220,240			# aesenc %xmm0, %xmm6
.byte	102,15,56,220,248			# aesenc %xmm0, %xmm7
	movups	-16(%rcx,%rax,1),%xmm0		# Load next round key
	jnz	.Lenc_loop6			# Loop until done

.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2
.byte	102,15,56,220,217			# aesenc %xmm1, %xmm3
.byte	102,15,56,220,225			# aesenc %xmm1, %xmm4
.byte	102,15,56,220,233			# aesenc %xmm1, %xmm5
.byte	102,15,56,220,241			# aesenc %xmm1, %xmm6
.byte	102,15,56,220,249			# aesenc %xmm1, %xmm7
.byte	102,15,56,221,208			# aesenclast %xmm0, %xmm2
.byte	102,15,56,221,216			# aesenclast %xmm0, %xmm3
.byte	102,15,56,221,224			# aesenclast %xmm0, %xmm4
.byte	102,15,56,221,232			# aesenclast %xmm0, %xmm5
.byte	102,15,56,221,240			# aesenclast %xmm0, %xmm6
.byte	102,15,56,221,248			# aesenclast %xmm0, %xmm7
	.byte	0xf3,0xc3				# rep ret: Return
.cfi_endproc					# CFI end
.size	_snts_aesni_encrypt6,.-_snts_aesni_encrypt6	# Set function size

# Internal function: _snts_aesni_decrypt6
# Decrypts 6 blocks of data in parallel.
.type	_snts_aesni_decrypt6,@function		# Define as a function
.align	16					# Align to 16-byte boundary
_snts_aesni_decrypt6:				# Function label
.cfi_startproc					# CFI start
	movups	(%rcx),%xmm0			# Load first round key
	shll	$4,%eax				# Calculate offset for key schedule
	movups	16(%rcx),%xmm1			# Load second round key
	xorps	%xmm0,%xmm2			# AddRoundKey for block 1
	pxor	%xmm0,%xmm3			# AddRoundKey for block 2
	pxor	%xmm0,%xmm4			# AddRoundKey for block 3
.byte	102,15,56,222,209			# aesdec %xmm1, %xmm2
	leaq	32(%rcx,%rax,1),%rcx		# Calculate end of key schedule
	negq	%rax				# Negate offset for loop countdown
.byte	102,15,56,222,217			# aesdec %xmm1, %xmm3
	pxor	%xmm0,%xmm5			# AddRoundKey for block 4
	pxor	%xmm0,%xmm6			# AddRoundKey for block 5
.byte	102,15,56,222,225			# aesdec %xmm1, %xmm4
	pxor	%xmm0,%xmm7			# AddRoundKey for block 6
	movups	(%rcx,%rax,1),%xmm0		# Load next round key
	addq	$16,%rax				# Adjust offset
	jmp	.Ldec_loop6_enter		# Jump to loop entry

.align	16					# Align loop
.Ldec_loop6:					# Loop for decrypting 6 blocks
.byte	102,15,56,222,209			# aesdec %xmm1, %xmm2
.byte	102,15,56,222,217			# aesdec %xmm1, %xmm3
.byte	102,15,56,222,225			# aesdec %xmm1, %xmm4
.Ldec_loop6_enter:				# Loop entry point
.byte	102,15,56,222,233			# aesdec %xmm1, %xmm5
.byte	102,15,56,222,241			# aesdec %xmm1, %xmm6
.byte	102,15,56,222,249			# aesdec %xmm1, %xmm7
	movups	(%rcx,%rax,1),%xmm1		# Load next round key
	addq	$32,%rax				# Update offset
.byte	102,15,56,222,208			# aesdec %xmm0, %xmm2
.byte	102,15,56,222,216			# aesdec %xmm0, %xmm3
.byte	102,15,56,222,224			# aesdec %xmm0, %xmm4
.byte	102,15,56,222,232			# aesdec %xmm0, %xmm5
.byte	102,15,56,222,240			# aesdec %xmm0, %xmm6
.byte	102,15,56,222,248			# aesdec %xmm0, %xmm7
	movups	-16(%rcx,%rax,1),%xmm0		# Load next round key
	jnz	.Ldec_loop6			# Loop until done

.byte	102,15,56,222,209			# aesdec %xmm1, %xmm2
.byte	102,15,56,222,217			# aesdec %xmm1, %xmm3
.byte	102,15,56,222,225			# aesdec %xmm1, %xmm4
.byte	102,15,56,222,233			# aesdec %xmm1, %xmm5
.byte	102,15,56,222,241			# aesdec %xmm1, %xmm6
.byte	102,15,56,222,249			# aesdec %xmm1, %xmm7
.byte	102,15,56,223,208			# aesdeclast %xmm0, %xmm2
.byte	102,15,56,223,216			# aesdeclast %xmm0, %xmm3
.byte	102,15,56,223,224			# aesdeclast %xmm0, %xmm4
.byte	102,15,56,223,232			# aesdeclast %xmm0, %xmm5
.byte	102,15,56,223,240			# aesdeclast %xmm0, %xmm6
.byte	102,15,56,223,248			# aesdeclast %xmm0, %xmm7
	.byte	0xf3,0xc3				# rep ret: Return
.cfi_endproc					# CFI end
.size	_snts_aesni_decrypt6,.-_snts_aesni_decrypt6	# Set function size

# Internal function: _snts_aesni_encrypt8
# Encrypts 8 blocks of data in parallel.
.type	_snts_aesni_encrypt8,@function		# Define as a function
.align	16					# Align to 16-byte boundary
_snts_aesni_encrypt8:				# Function label
.cfi_startproc					# CFI start
	movups	(%rcx),%xmm0			# Load first round key
	shll	$4,%eax				# Calculate offset for key schedule
	movups	16(%rcx),%xmm1			# Load second round key
	xorps	%xmm0,%xmm2			# AddRoundKey for block 1
	xorps	%xmm0,%xmm3			# AddRoundKey for block 2
	pxor	%xmm0,%xmm4			# AddRoundKey for block 3
	pxor	%xmm0,%xmm5			# AddRoundKey for block 4
	pxor	%xmm0,%xmm6			# AddRoundKey for block 5
	leaq	32(%rcx,%rax,1),%rcx		# Calculate end of key schedule
	negq	%rax				# Negate offset for loop countdown
.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2
	pxor	%xmm0,%xmm7			# AddRoundKey for block 6
	pxor	%xmm0,%xmm8			# AddRoundKey for block 7
.byte	102,15,56,220,217			# aesenc %xmm1, %xmm3
	pxor	%xmm0,%xmm9			# AddRoundKey for block 8
	movups	(%rcx,%rax,1),%xmm0		# Load next round key
	addq	$16,%rax				# Adjust offset
	jmp	.Lenc_loop8_inner		# Jump to inner loop

.align	16					# Align loop
.Lenc_loop8:					# Loop for encrypting 8 blocks
.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2
.byte	102,15,56,220,217			# aesenc %xmm1, %xmm3
.Lenc_loop8_inner:				# Inner loop label
.byte	102,15,56,220,225			# aesenc %xmm1, %xmm4
.byte	102,15,56,220,233			# aesenc %xmm1, %xmm5
.byte	102,15,56,220,241			# aesenc %xmm1, %xmm6
.byte	102,15,56,220,249			# aesenc %xmm1, %xmm7
.byte	102,68,15,56,220,193			# aesenc %xmm1, %xmm8
.byte	102,68,15,56,220,201			# aesenc %xmm1, %xmm9
.Lenc_loop8_enter:				# Loop entry point
	movups	(%rcx,%rax,1),%xmm1		# Load next round key
	addq	$32,%rax				# Update offset
.byte	102,15,56,220,208			# aesenc %xmm0, %xmm2
.byte	102,15,56,220,216			# aesenc %xmm0, %xmm3
.byte	102,15,56,220,224			# aesenc %xmm0, %xmm4
.byte	102,15,56,220,232			# aesenc %xmm0, %xmm5
.byte	102,15,56,220,240			# aesenc %xmm0, %xmm6
.byte	102,15,56,220,248			# aesenc %xmm0, %xmm7
.byte	102,68,15,56,220,192			# aesenc %xmm0, %xmm8
.byte	102,68,15,56,220,200			# aesenc %xmm0, %xmm9
	movups	-16(%rcx,%rax,1),%xmm0		# Load next round key
	jnz	.Lenc_loop8			# Loop until done

.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2
.byte	102,15,56,220,217			# aesenc %xmm1, %xmm3
.byte	102,15,56,220,225			# aesenc %xmm1, %xmm4
.byte	102,15,56,220,233			# aesenc %xmm1, %xmm5
.byte	102,15,56,220,241			# aesenc %xmm1, %xmm6
.byte	102,15,56,220,249			# aesenc %xmm1, %xmm7
.byte	102,68,15,56,220,193			# aesenc %xmm1, %xmm8
.byte	102,68,15,56,220,201			# aesenc %xmm1, %xmm9
.byte	102,15,56,221,208			# aesenclast %xmm0, %xmm2
.byte	102,15,56,221,216			# aesenclast %xmm0, %xmm3
.byte	102,15,56,221,224			# aesenclast %xmm0, %xmm4
.byte	102,15,56,221,232			# aesenclast %xmm0, %xmm5
.byte	102,15,56,221,240			# aesenclast %xmm0, %xmm6
.byte	102,15,56,221,248			# aesenclast %xmm0, %xmm7
.byte	102,68,15,56,221,192			# aesenclast %xmm0, %xmm8
.byte	102,68,15,56,221,200			# aesenclast %xmm0, %xmm9
	.byte	0xf3,0xc3				# rep ret: Return
.cfi_endproc					# CFI end
.size	_snts_aesni_encrypt8,.-_snts_aesni_encrypt8	# Set function size

# Internal function: _snts_aesni_decrypt8
# Decrypts 8 blocks of data in parallel.
.type	_snts_aesni_decrypt8,@function		# Define as a function
.align	16					# Align to 16-byte boundary
_snts_aesni_decrypt8:				# Function label
.cfi_startproc					# CFI start
	movups	(%rcx),%xmm0			# Load first round key
	shll	$4,%eax				# Calculate offset for key schedule
	movups	16(%rcx),%xmm1			# Load second round key
	xorps	%xmm0,%xmm2			# AddRoundKey for block 1
	xorps	%xmm0,%xmm3			# AddRoundKey for block 2
	pxor	%xmm0,%xmm4			# AddRoundKey for block 3
	pxor	%xmm0,%xmm5			# AddRoundKey for block 4
	pxor	%xmm0,%xmm6			# AddRoundKey for block 5
	leaq	32(%rcx,%rax,1),%rcx		# Calculate end of key schedule
	negq	%rax				# Negate offset for loop countdown
.byte	102,15,56,222,209			# aesdec %xmm1, %xmm2
	pxor	%xmm0,%xmm7			# AddRoundKey for block 6
	pxor	%xmm0,%xmm8			# AddRoundKey for block 7
.byte	102,15,56,222,217			# aesdec %xmm1, %xmm3
	pxor	%xmm0,%xmm9			# AddRoundKey for block 8
	movups	(%rcx,%rax,1),%xmm0		# Load next round key
	addq	$16,%rax				# Adjust offset
	jmp	.Ldec_loop8_inner		# Jump to inner loop

.align	16					# Align loop
.Ldec_loop8:					# Loop for decrypting 8 blocks
.byte	102,15,56,222,209			# aesdec %xmm1, %xmm2
.byte	102,15,56,222,217			# aesdec %xmm1, %xmm3
.Ldec_loop8_inner:				# Inner loop label
.byte	102,15,56,222,225			# aesdec %xmm1, %xmm4
.byte	102,15,56,222,233			# aesdec %xmm1, %xmm5
.byte	102,15,56,222,241			# aesdec %xmm1, %xmm6
.byte	102,15,56,222,249			# aesdec %xmm1, %xmm7
.byte	102,68,15,56,222,193			# aesdec %xmm1, %xmm8
.byte	102,68,15,56,222,201			# aesdec %xmm1, %xmm9
.Ldec_loop8_enter:				# Loop entry point
	movups	(%rcx,%rax,1),%xmm1		# Load next round key
	addq	$32,%rax				# Update offset
.byte	102,15,56,222,208			# aesdec %xmm0, %xmm2
.byte	102,15,56,222,216			# aesdec %xmm0, %xmm3
.byte	102,15,56,222,224			# aesdec %xmm0, %xmm4
.byte	102,15,56,222,232			# aesdec %xmm0, %xmm5
.byte	102,15,56,222,240			# aesdec %xmm0, %xmm6
.byte	102,15,56,222,248			# aesdec %xmm0, %xmm7
.byte	102,68,15,56,222,192			# aesdec %xmm0, %xmm8
.byte	102,68,15,56,222,200			# aesdec %xmm0, %xmm9
	movups	-16(%rcx,%rax,1),%xmm0		# Load next round key
	jnz	.Ldec_loop8			# Loop until done

.byte	102,15,56,222,209			# aesdec %xmm1, %xmm2
.byte	102,15,56,222,217			# aesdec %xmm1, %xmm3
.byte	102,15,56,222,225			# aesdec %xmm1, %xmm4
.byte	102,15,56,222,233			# aesdec %xmm1, %xmm5
.byte	102,15,56,222,241			# aesdec %xmm1, %xmm6
.byte	102,15,56,222,249			# aesdec %xmm1, %xmm7
.byte	102,68,15,56,222,193			# aesdec %xmm1, %xmm8
.byte	102,68,15,56,222,201			# aesdec %xmm1, %xmm9
.byte	102,15,56,223,208			# aesdeclast %xmm0, %xmm2
.byte	102,15,56,223,216			# aesdeclast %xmm0, %xmm3
.byte	102,15,56,223,224			# aesdeclast %xmm0, %xmm4
.byte	102,15,56,223,232			# aesdeclast %xmm0, %xmm5
.byte	102,15,56,223,240			# aesdeclast %xmm0, %xmm6
.byte	102,15,56,223,248			# aesdeclast %xmm0, %xmm7
.byte	102,68,15,56,223,192			# aesdeclast %xmm0, %xmm8
.byte	102,68,15,56,223,200			# aesdeclast %xmm0, %xmm9
	.byte	0xf3,0xc3				# rep ret: Return
.cfi_endproc					# CFI end
.size	_snts_aesni_decrypt8,.-_snts_aesni_decrypt8	# Set function size

# Function: snts_aesni_ecb_encrypt
# Encrypts/Decrypts multiple blocks using AES in ECB mode.
.globl	snts_aesni_ecb_encrypt			# Make visible to linker
.type	snts_aesni_ecb_encrypt,@function	# Define as function
.align	16					# Align to 16-byte boundary
snts_aesni_ecb_encrypt:				# Function label
.cfi_startproc					# CFI start
.byte	243,15,30,250				# endbr64 instruction
	andq	$-16,%rdx			# Align length to 16-byte block boundary
	jz	.Lecb_ret			# If length is zero, return

	movl	240(%rcx),%eax			# Load number of rounds
	movups	(%rcx),%xmm0			# Load first round key
	movq	%rcx,%r11			# Save key schedule pointer
	movl	%eax,%r10d			# Save number of rounds
	testl	%r8d,%r8d			# Check encryption/decryption flag
	jz	.Lecb_decrypt			# If zero, jump to decryption

	cmpq	$0x80,%rdx			# Compare length with 128 bytes (8 blocks)
	jb	.Lecb_enc_tail			# If less, handle tail

	movdqu	(%rdi),%xmm2			# Load block 1
	movdqu	16(%rdi),%xmm3			# Load block 2
	movdqu	32(%rdi),%xmm4			# Load block 3
	movdqu	48(%rdi),%xmm5			# Load block 4
	movdqu	64(%rdi),%xmm6			# Load block 5
	movdqu	80(%rdi),%xmm7			# Load block 6
	movdqu	96(%rdi),%xmm8			# Load block 7
	movdqu	112(%rdi),%xmm9			# Load block 8
	leaq	128(%rdi),%rdi			# Advance input pointer
	subq	$0x80,%rdx			# Decrement length
	jmp	.Lecb_enc_loop8_enter		# Jump to loop entry

.align	16					# Align loop
.Lecb_enc_loop8:				# Loop for encrypting 8 blocks at a time
	movups	%xmm2,(%rsi)			# Store encrypted block 1
	movq	%r11,%rcx			# Restore key schedule pointer
	movdqu	(%rdi),%xmm2			# Load next block 1
	movl	%r10d,%eax			# Restore number of rounds
	movups	%xmm3,16(%rsi)			# Store encrypted block 2
	movdqu	16(%rdi),%xmm3			# Load next block 2
	movups	%xmm4,32(%rsi)			# Store encrypted block 3
	movdqu	32(%rdi),%xmm4			# Load next block 3
	movups	%xmm5,48(%rsi)			# Store encrypted block 4
	movdqu	48(%rdi),%xmm5			# Load next block 4
	movups	%xmm6,64(%rsi)			# Store encrypted block 5
	movdqu	64(%rdi),%xmm6			# Load next block 5
	movups	%xmm7,80(%rsi)			# Store encrypted block 6
	movdqu	80(%rdi),%xmm7			# Load next block 6
	movups	%xmm8,96(%rsi)			# Store encrypted block 7
	movdqu	96(%rdi),%xmm8			# Load next block 7
	movups	%xmm9,112(%rsi)			# Store encrypted block 8
	leaq	128(%rsi),%rsi			# Advance output pointer
	movdqu	112(%rdi),%xmm9			# Load next block 8
	leaq	128(%rdi),%rdi			# Advance input pointer
.Lecb_enc_loop8_enter:				# Loop entry point

	call	_snts_aesni_encrypt8		# Call 8-block encryption function

	subq	$0x80,%rdx			# Decrement length
	jnc	.Lecb_enc_loop8			# Loop if more blocks remain

	movups	%xmm2,(%rsi)			# Store final set of 8 blocks
	movq	%r11,%rcx			# Restore key schedule pointer
	movups	%xmm3,16(%rsi)
	movl	%r10d,%eax			# Restore number of rounds
	movups	%xmm4,32(%rsi)
	movups	%xmm5,48(%rsi)
	movups	%xmm6,64(%rsi)
	movups	%xmm7,80(%rsi)
	movups	%xmm8,96(%rsi)
	movups	%xmm9,112(%rsi)
	leaq	128(%rsi),%rsi			# Advance output pointer
	addq	$0x80,%rdx			# Adjust length
	jz	.Lecb_ret			# If done, return

.Lecb_enc_tail:					# Handle remaining blocks (less than 8)
	movups	(%rdi),%xmm2			# Load block 1
	cmpq	$0x20,%rdx			# Compare length with 32
	jb	.Lecb_enc_one			# If less, handle 1 block
	movups	16(%rdi),%xmm3			# Load block 2
	je	.Lecb_enc_two			# If equal, handle 2 blocks
	movups	32(%rdi),%xmm4			# Load block 3
	cmpq	$0x40,%rdx			# Compare with 64
	jb	.Lecb_enc_three			# If less, handle 3 blocks
	movups	48(%rdi),%xmm5			# Load block 4
	je	.Lecb_enc_four			# If equal, handle 4 blocks
	movups	64(%rdi),%xmm6			# Load block 5
	cmpq	$0x60,%rdx			# Compare with 96
	jb	.Lecb_enc_five			# If less, handle 5 blocks
	movups	80(%rdi),%xmm7			# Load block 6
	je	.Lecb_enc_six			# If equal, handle 6 blocks
	movdqu	96(%rdi),%xmm8			# Load block 7
	xorps	%xmm9,%xmm9			# Zero out XMM9
	call	_snts_aesni_encrypt8		# Call 8-block encryption (7 used)
	movups	%xmm2,(%rsi)			# Store results
	movups	%xmm3,16(%rsi)
	movups	%xmm4,32(%rsi)
	movups	%xmm5,48(%rsi)
	movups	%xmm6,64(%rsi)
	movups	%xmm7,80(%rsi)
	movups	%xmm8,96(%rsi)
	jmp	.Lecb_ret			# Return

.align	16					# Align
.Lecb_enc_one:					# Handle 1 remaining block
	movups	(%rcx),%xmm0			# Load round key
	movups	16(%rcx),%xmm1			# Load round key
	leaq	32(%rcx),%rcx			# Advance key pointer
	xorps	%xmm0,%xmm2			# AddRoundKey
.Loop_enc1_3:					# Encryption loop
.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2
	decl	%eax				# Decrement round counter
	movups	(%rcx),%xmm1			# Load next key
	leaq	16(%rcx),%rcx			# Advance key pointer
	jnz	.Loop_enc1_3			# Loop
.byte	102,15,56,221,209			# aesenclast %xmm1, %xmm2
	movups	%xmm2,(%rsi)			# Store result
	jmp	.Lecb_ret			# Return

.align	16					# Align
.Lecb_enc_two:					# Handle 2 remaining blocks
	call	_snts_aesni_encrypt2		# Call 2-block encryption
	movups	%xmm2,(%rsi)			# Store results
	movups	%xmm3,16(%rsi)
	jmp	.Lecb_ret			# Return

.align	16					# Align
.Lecb_enc_three:				# Handle 3 remaining blocks
	call	_snts_aesni_encrypt3		# Call 3-block encryption
	movups	%xmm2,(%rsi)			# Store results
	movups	%xmm3,16(%rsi)
	movups	%xmm4,32(%rsi)
	jmp	.Lecb_ret			# Return

.align	16					# Align
.Lecb_enc_four:					# Handle 4 remaining blocks
	call	_snts_aesni_encrypt4		# Call 4-block encryption
	movups	%xmm2,(%rsi)			# Store results
	movups	%xmm3,16(%rsi)
	movups	%xmm4,32(%rsi)
	movups	%xmm5,48(%rsi)
	jmp	.Lecb_ret			# Return

.align	16					# Align
.Lecb_enc_five:					# Handle 5 remaining blocks
	xorps	%xmm7,%xmm7			# Zero out XMM7
	call	_snts_aesni_encrypt6		# Call 6-block encryption (5 used)
	movups	%xmm2,(%rsi)			# Store results
	movups	%xmm3,16(%rsi)
	movups	%xmm4,32(%rsi)
	movups	%xmm5,48(%rsi)
	movups	%xmm6,64(%rsi)
	jmp	.Lecb_ret			# Return

.align	16					# Align
.Lecb_enc_six:					# Handle 6 remaining blocks
	call	_snts_aesni_encrypt6		# Call 6-block encryption
	movups	%xmm2,(%rsi)			# Store results
	movups	%xmm3,16(%rsi)
	movups	%xmm4,32(%rsi)
	movups	%xmm5,48(%rsi)
	movups	%xmm6,64(%rsi)
	movups	%xmm7,80(%rsi)
	jmp	.Lecb_ret			# Return

.align	16					# Align
.Lecb_decrypt:					# Decryption path for ECB
	cmpq	$0x80,%rdx			# Compare length with 128
	jb	.Lecb_dec_tail			# If less, handle tail

	movdqu	(%rdi),%xmm2			# Load 8 blocks of ciphertext
	movdqu	16(%rdi),%xmm3
	movdqu	32(%rdi),%xmm4
	movdqu	48(%rdi),%xmm5
	movdqu	64(%rdi),%xmm6
	movdqu	80(%rdi),%xmm7
	movdqu	96(%rdi),%xmm8
	movdqu	112(%rdi),%xmm9
	leaq	128(%rdi),%rdi			# Advance input pointer
	subq	$0x80,%rdx			# Decrement length
	jmp	.Lecb_dec_loop8_enter		# Jump to loop entry

.align	16					# Align loop
.Lecb_dec_loop8:				# Loop for decrypting 8 blocks at a time
	movups	%xmm2,(%rsi)			# Store decrypted block 1
	movq	%r11,%rcx			# Restore key schedule pointer
	movdqu	(%rdi),%xmm2			# Load next block 1
	movl	%r10d,%eax			# Restore number of rounds
	movups	%xmm3,16(%rsi)			# Store decrypted block 2
	movdqu	16(%rdi),%xmm3			# Load next block 2
	movups	%xmm4,32(%rsi)			# Store decrypted block 3
	movdqu	32(%rdi),%xmm4			# Load next block 3
	movups	%xmm5,48(%rsi)			# Store decrypted block 4
	movdqu	48(%rdi),%xmm5			# Load next block 4
	movups	%xmm6,64(%rsi)			# Store decrypted block 5
	movdqu	64(%rdi),%xmm6			# Load next block 5
	movups	%xmm7,80(%rsi)			# Store decrypted block 6
	movdqu	80(%rdi),%xmm7			# Load next block 6
	movups	%xmm8,96(%rsi)			# Store decrypted block 7
	movdqu	96(%rdi),%xmm8			# Load next block 7
	movups	%xmm9,112(%rsi)			# Store decrypted block 8
	leaq	128(%rsi),%rsi			# Advance output pointer
	movdqu	112(%rdi),%xmm9			# Load next block 8
	leaq	128(%rdi),%rdi			# Advance input pointer
.Lecb_dec_loop8_enter:				# Loop entry point

	call	_snts_aesni_decrypt8		# Call 8-block decryption function

	movups	(%r11),%xmm0			# Load first round key
	subq	$0x80,%rdx			# Decrement length
	jnc	.Lecb_dec_loop8			# Loop if more blocks remain

	movups	%xmm2,(%rsi)			# Store final set of 8 blocks
	pxor	%xmm2,%xmm2			# Clear register
	movq	%r11,%rcx			# Restore key schedule pointer
	movups	%xmm3,16(%rsi)
	pxor	%xmm3,%xmm3			# Clear register
	movl	%r10d,%eax			# Restore number of rounds
	movups	%xmm4,32(%rsi)
	pxor	%xmm4,%xmm4			# Clear register
	movups	%xmm5,48(%rsi)
	pxor	%xmm5,%xmm5			# Clear register
	movups	%xmm6,64(%rsi)
	pxor	%xmm6,%xmm6			# Clear register
	movups	%xmm7,80(%rsi)
	pxor	%xmm7,%xmm7			# Clear register
	movups	%xmm8,96(%rsi)
	pxor	%xmm8,%xmm8			# Clear register
	movups	%xmm9,112(%rsi)
	pxor	%xmm9,%xmm9			# Clear register
	leaq	128(%rsi),%rsi			# Advance output pointer
	addq	$0x80,%rdx			# Adjust length
	jz	.Lecb_ret			# If done, return

.Lecb_dec_tail:					# Handle remaining blocks for decryption
	movups	(%rdi),%xmm2			# Load block 1
	cmpq	$0x20,%rdx			# Compare length with 32
	jb	.Lecb_dec_one			# If less, handle 1 block
	movups	16(%rdi),%xmm3			# Load block 2
	je	.Lecb_dec_two			# If equal, handle 2 blocks
	movups	32(%rdi),%xmm4			# Load block 3
	cmpq	$0x40,%rdx			# Compare with 64
	jb	.Lecb_dec_three			# If less, handle 3 blocks
	movups	48(%rdi),%xmm5			# Load block 4
	je	.Lecb_dec_four			# If equal, handle 4 blocks
	movups	64(%rdi),%xmm6			# Load block 5
	cmpq	$0x60,%rdx			# Compare with 96
	jb	.Lecb_dec_five			# If less, handle 5 blocks
	movups	80(%rdi),%xmm7			# Load block 6
	je	.Lecb_dec_six			# If equal, handle 6 blocks
	movups	96(%rdi),%xmm8			# Load block 7
	movups	(%rcx),%xmm0			# Load round key
	xorps	%xmm9,%xmm9			# Zero out XMM9
	call	_snts_aesni_decrypt8		# Call 8-block decryption (7 used)
	movups	%xmm2,(%rsi)			# Store results and clear registers
	pxor	%xmm2,%xmm2
	movups	%xmm3,16(%rsi)
	pxor	%xmm3,%xmm3
	movups	%xmm4,32(%rsi)
	pxor	%xmm4,%xmm4
	movups	%xmm5,48(%rsi)
	pxor	%xmm5,%xmm5
	movups	%xmm6,64(%rsi)
	pxor	%xmm6,%xmm6
	movups	%xmm7,80(%rsi)
	pxor	%xmm7,%xmm7
	movups	%xmm8,96(%rsi)
	pxor	%xmm8,%xmm8
	pxor	%xmm9,%xmm9
	jmp	.Lecb_ret			# Return

.align	16					# Align
.Lecb_dec_one:					# Handle 1 remaining block for decryption
	movups	(%rcx),%xmm0			# Load round key
	movups	16(%rcx),%xmm1			# Load round key
	leaq	32(%rcx),%rcx			# Advance key pointer
	xorps	%xmm0,%xmm2			# AddRoundKey
.Loop_dec1_4:					# Decryption loop
.byte	102,15,56,222,209			# aesdec %xmm1, %xmm2
	decl	%eax				# Decrement round counter
	movups	(%rcx),%xmm1			# Load next key
	leaq	16(%rcx),%rcx			# Advance key pointer
	jnz	.Loop_dec1_4			# Loop
.byte	102,15,56,223,209			# aesdeclast %xmm1, %xmm2
	movups	%xmm2,(%rsi)			# Store result
	pxor	%xmm2,%xmm2			# Clear register
	jmp	.Lecb_ret			# Return

.align	16					# Align
.Lecb_dec_two:					# Handle 2 remaining blocks for decryption
	call	_snts_aesni_decrypt2		# Call 2-block decryption
	movups	%xmm2,(%rsi)			# Store results and clear registers
	pxor	%xmm2,%xmm2
	movups	%xmm3,16(%rsi)
	pxor	%xmm3,%xmm3
	jmp	.Lecb_ret			# Return

.align	16					# Align
.Lecb_dec_three:				# Handle 3 remaining blocks for decryption
	call	_snts_aesni_decrypt3		# Call 3-block decryption
	movups	%xmm2,(%rsi)			# Store results and clear registers
	pxor	%xmm2,%xmm2
	movups	%xmm3,16(%rsi)
	pxor	%xmm3,%xmm3
	movups	%xmm4,32(%rsi)
	pxor	%xmm4,%xmm4
	jmp	.Lecb_ret			# Return

.align	16					# Align
.Lecb_dec_four:					# Handle 4 remaining blocks for decryption
	call	_snts_aesni_decrypt4		# Call 4-block decryption
	movups	%xmm2,(%rsi)			# Store results and clear registers
	pxor	%xmm2,%xmm2
	movups	%xmm3,16(%rsi)
	pxor	%xmm3,%xmm3
	movups	%xmm4,32(%rsi)
	pxor	%xmm4,%xmm4
	movups	%xmm5,48(%rsi)
	pxor	%xmm5,%xmm5
	jmp	.Lecb_ret			# Return

.align	16					# Align
.Lecb_dec_five:					# Handle 5 remaining blocks for decryption
	xorps	%xmm7,%xmm7			# Zero out XMM7
	call	_snts_aesni_decrypt6		# Call 6-block decryption (5 used)
	movups	%xmm2,(%rsi)			# Store results and clear registers
	pxor	%xmm2,%xmm2
	movups	%xmm3,16(%rsi)
	pxor	%xmm3,%xmm3
	movups	%xmm4,32(%rsi)
	pxor	%xmm4,%xmm4
	movups	%xmm5,48(%rsi)
	pxor	%xmm5,%xmm5
	movups	%xmm6,64(%rsi)
	pxor	%xmm6,%xmm6
	pxor	%xmm7,%xmm7
	jmp	.Lecb_ret			# Return

.align	16					# Align
.Lecb_dec_six:					# Handle 6 remaining blocks for decryption
	call	_snts_aesni_decrypt6		# Call 6-block decryption
	movups	%xmm2,(%rsi)			# Store results and clear registers
	pxor	%xmm2,%xmm2
	movups	%xmm3,16(%rsi)
	pxor	%xmm3,%xmm3
	movups	%xmm4,32(%rsi)
	pxor	%xmm4,%xmm4
	movups	%xmm5,48(%rsi)
	pxor	%xmm5,%xmm5
	movups	%xmm6,64(%rsi)
	pxor	%xmm6,%xmm6
	movups	%xmm7,80(%rsi)
	pxor	%xmm7,%xmm7

.Lecb_ret:					# Return point for ECB
	xorps	%xmm0,%xmm0			# Clear registers
	pxor	%xmm1,%xmm1
	.byte	0xf3,0xc3				# rep ret: Return
.cfi_endproc					# CFI end
.size	snts_aesni_ecb_encrypt,.-snts_aesni_ecb_encrypt	# Set function size

# Function: snts_aesni_ctr32_encrypt_blocks
# Encrypts multiple blocks using AES in CTR mode with a 32-bit counter.
.globl	snts_aesni_ctr32_encrypt_blocks		# Make visible to linker
.type	snts_aesni_ctr32_encrypt_blocks,@function	# Define as function
.align	16					# Align to 16-byte boundary
snts_aesni_ctr32_encrypt_blocks:		# Function label
.cfi_startproc					# CFI start
.byte	243,15,30,250				# endbr64 instruction
	cmpq	$1,%rdx				# Compare number of blocks to 1
	jne	.Lctr32_bulk			# If not 1, jump to bulk processing

	# Single block encryption path
	movups	(%r8),%xmm2			# Load counter block
	movups	(%rdi),%xmm3			# Load plaintext
	movl	240(%rcx),%edx			# Load number of rounds
	movups	(%rcx),%xmm0			# Load first round key
	movups	16(%rcx),%xmm1			# Load second round key
	leaq	32(%rcx),%rcx			# Advance key pointer
	xorps	%xmm0,%xmm2			# AddRoundKey on counter
.Loop_enc1_7:					# Encryption loop for counter
.byte	102,15,56,220,209			# aesenc %xmm1, %xmm2
	decl	%edx				# Decrement round counter
	movups	(%rcx),%xmm1			# Load next key
	leaq	16(%rcx),%rcx			# Advance key pointer
	jnz	.Loop_enc1_7			# Loop
.byte	102,15,56,221,209			# aesenclast %xmm1, %xmm2
	pxor	%xmm0,%xmm0			# Clear registers
	pxor	%xmm1,%xmm1
	xorps	%xmm3,%xmm2			# XOR encrypted counter with plaintext
	pxor	%xmm3,%xmm3
	movups	%xmm2,(%rsi)			# Store ciphertext
	xorps	%xmm2,%xmm2
	jmp	.Lctr32_epilogue		# Jump to epilogue

.align	16					# Align
.Lctr32_bulk:					# Bulk processing path for CTR
	leaq	(%rsp),%r11			# Save stack pointer
.cfi_def_cfa_register	%r11
	pushq	%rbp				# Save base pointer
.cfi_offset	%rbp,-16
	subq	$128,%rsp			# Allocate stack space
	andq	$-16,%rsp			# Align stack

	movdqu	(%r8),%xmm2			# Load counter block
	movdqu	(%rcx),%xmm0			# Load first round key
	movl	12(%r8),%r8d			# Load counter value
	pxor	%xmm0,%xmm2			# AddRoundKey on counter
	movl	12(%rcx),%ebp			# Load value from key schedule
	movdqa	%xmm2,0(%rsp)			# Save counter state
	bswapl	%r8d				# Byte swap counter
	movdqa	%xmm2,%xmm3			# Copy counter state
	movdqa	%xmm2,%xmm4
	movdqa	%xmm2,%xmm5
	movdqa	%xmm2,64(%rsp)
	movdqa	%xmm2,80(%rsp)
	movdqa	%xmm2,96(%rsp)
	movq	%rdx,%r10			# Save number of blocks
	movdqa	%xmm2,112(%rsp)

	leaq	1(%r8),%rax			# Increment counter
	leaq	2(%r8),%rdx			# Increment counter
	bswapl	%eax				# Byte swap
	bswapl	%edx				# Byte swap
	xorl	%ebp,%eax			# XOR with key schedule value
	xorl	%ebp,%edx
.byte	102,15,58,34,216,3			# pshufb instruction
	leaq	3(%r8),%rax			# Increment counter
	movdqa	%xmm3,16(%rsp)			# Save counter state
.byte	102,15,58,34,226,3			# pshufb instruction
	bswapl	%eax				# Byte swap
	movq	%r10,%rdx			# Restore number of blocks
	leaq	4(%r8),%r10			# Increment counter
	movdqa	%xmm4,32(%rsp)			# Save counter state
	xorl	%ebp,%eax			# XOR
	bswapl	%r10d				# Byte swap
.byte	102,15,58,34,232,3			# pshufb instruction
	xorl	%ebp,%r10d			# XOR
	movdqa	%xmm5,48(%rsp)			# Save counter state
	leaq	5(%r8),%r9			# Increment counter
	movl	%r10d,64+12(%rsp)		# Store counter value
	bswapl	%r9d				# Byte swap
	leaq	6(%r8),%r10			# Increment counter
	movl	240(%rcx),%eax			# Load number of rounds
	xorl	%ebp,%r9d			# XOR
	bswapl	%r10d				# Byte swap
	movl	%r9d,80+12(%rsp)		# Store counter value
	xorl	%ebp,%r10d			# XOR
	leaq	7(%r8),%r9			# Increment counter
	movl	%r10d,96+12(%rsp)		# Store counter value
	bswapl	%r9d				# Byte swap
	movl	_OPENSSL_ia32cap_P+4(%rip),%r10d	# Load capability flags
	xorl	%ebp,%r9d			# XOR
	andl	$71303168,%r10d			# Check for AVX/XTS support
	movl	%r9d,112+12(%rsp)		# Store counter value

	movups	16(%rcx),%xmm1			# Load second round key

	movdqa	64(%rsp),%xmm6			# Load counter states
	movdqa	80(%rsp),%xmm7

	cmpq	$8,%rdx				# Compare blocks with 8
	jb	.Lctr32_tail			# If less, handle tail

	subq	$6,%rdx				# Adjust block count
	cmpl	$4194304,%r10d			# Check for VAES support
	je	.Lctr32_6x			# If so, use 6-block loop

	leaq	128(%rcx),%rcx			# Advance key pointer
	subq	$2,%rdx				# Adjust block count
	jmp	.Lctr32_loop8			# Jump to 8-block loop

.align	16					# Align
.Lctr32_6x:					# 6-block loop for VAES
	shll	$4,%eax				# Calculate key offset
	movl	$48,%r10d			# Set offset
	bswapl	%ebp				# Byte swap
	leaq	32(%rcx,%rax,1),%rcx		# Calculate end of key schedule
	subq	%rax,%r10			# Adjust offset
	jmp	.Lctr32_loop6			# Jump to loop

.align	16					# Align
.Lctr32_loop6:					# 6-block encryption loop
	addl	$6,%r8d				# Increment counter base
	movups	-48(%rcx,%r10,1),%xmm0		# Load round key
.byte	102,15,56,220,209			# aesenc
	movl	%r8d,%eax			# Get counter
	xorl	%ebp,%eax			# XOR
.byte	102,15,56,220,217			# aesenc
.byte	0x0f,0x38,0xf1,0x44,0x24,12		# psrldq
	leal	1(%r8),%eax			# Increment counter
.byte	102,15,56,220,225			# aesenc
	xorl	%ebp,%eax			# XOR
.byte	0x0f,0x38,0xf1,0x44,0x24,28		# psrldq
.byte	102,15,56,220,233			# aesenc
	leal	2(%r8),%eax			# Increment counter
	xorl	%ebp,%eax			# XOR
.byte	102,15,56,220,241			# aesenc
.byte	0x0f,0x38,0xf1,0x44,0x24,44		# psrldq
	leal	3(%r8),%eax			# Increment counter
.byte	102,15,56,220,249			# aesenc
	movups	-32(%rcx,%r10,1),%xmm1		# Load round key
	xorl	%ebp,%eax			# XOR

.byte	102,15,56,220,208			# aesenc
.byte	0x0f,0x38,0xf1,0x44,0x24,60		# psrldq
	leal	4(%r8),%eax			# Increment counter
.byte	102,15,56,220,216			# aesenc
	xorl	%ebp,%eax			# XOR
.byte	0x0f,0x38,0xf1,0x44,0x24,76		# psrldq
.byte	102,15,56,220,224			# aesenc
	leal	5(%r8),%eax			# Increment counter
	xorl	%ebp,%eax			# XOR
.byte	102,15,56,220,232			# aesenc
.byte	0x0f,0x38,0xf1,0x44,0x24,92		# psrldq
	movq	%r10,%rax			# Get offset
.byte	102,15,56,220,240			# aesenc
.byte	102,15,56,220,248			# aesenc
	movups	-16(%rcx,%r10,1),%xmm0		# Load round key

	call	.Lenc_loop6			# Call inner loop

	movdqu	(%rdi),%xmm8			# Load 6 blocks of plaintext
	movdqu	16(%rdi),%xmm9
	movdqu	32(%rdi),%xmm10
	movdqu	48(%rdi),%xmm11
	movdqu	64(%rdi),%xmm12
	movdqu	80(%rdi),%xmm13
	leaq	96(%rdi),%rdi			# Advance input pointer
	movups	-64(%rcx,%r10,1),%xmm1		# Load round key
	pxor	%xmm2,%xmm8			# XOR with encrypted counters
	movaps	0(%rsp),%xmm2
	pxor	%xmm3,%xmm9
	movaps	16(%rsp),%xmm3
	pxor	%xmm4,%xmm10
	movaps	32(%rsp),%xmm4
	pxor	%xmm5,%xmm11
	movaps	48(%rsp),%xmm5
	pxor	%xmm6,%xmm12
	movaps	64(%rsp),%xmm6
	pxor	%xmm7,%xmm13
	movaps	80(%rsp),%xmm7
	movdqu	%xmm8,(%rsi)			# Store 6 blocks of ciphertext
	movdqu	%xmm9,16(%rsi)
	movdqu	%xmm10,32(%rsi)
	movdqu	%xmm11,48(%rsi)
	movdqu	%xmm12,64(%rsi)
	movdqu	%xmm13,80(%rsi)
	leaq	96(%rsi),%rsi			# Advance output pointer

	subq	$6,%rdx				# Decrement block count
	jnc	.Lctr32_loop6			# Loop if more blocks

	addq	$6,%rdx				# Adjust block count
	jz	.Lctr32_done			# If done, finish

	leal	-48(%r10),%eax			# Calculate remaining key offset
	leaq	-80(%rcx,%r10,1),%rcx		# Adjust key pointer
	negl	%eax				# Negate
	shrl	$4,%eax				# Shift
	jmp	.Lctr32_tail			# Handle tail

.align	32					# Align
.Lctr32_loop8:					# 8-block encryption loop
	addl	$8,%r8d				# Increment counter base
	movdqa	96(%rsp),%xmm8			# Load counter states
.byte	102,15,56,220,209			# aesenc
	movl	%r8d,%r9d			# Get counter
	movdqa	112(%rsp),%xmm9
.byte	102,15,56,220,217			# aesenc
	bswapl	%r9d				# Byte swap
	movups	32-128(%rcx),%xmm0		# Load round key
.byte	102,15,56,220,225			# aesenc
	xorl	%ebp,%r9d			# XOR
	nop					# Align
.byte	102,15,56,220,233			# aesenc
	movl	%r9d,0+12(%rsp)			# Store counter
	leaq	1(%r8),%r9			# Increment counter
.byte	102,15,56,220,241			# aesenc
.byte	102,15,56,220,249			# aesenc
.byte	102,68,15,56,220,193			# aesenc
.byte	102,68,15,56,220,201			# aesenc
	movups	48-128(%rcx),%xmm1		# Load round key
	bswapl	%r9d				# Byte swap
.byte	102,15,56,220,208			# aesenc
.byte	102,15,56,220,216			# aesenc
	xorl	%ebp,%r9d			# XOR
.byte	0x66,0x90				# NOP
.byte	102,15,56,220,224			# aesenc
.byte	102,15,56,220,232			# aesenc
	movl	%r9d,16+12(%rsp)		# Store counter
	leaq	2(%r8),%r9			# Increment counter
.byte	102,15,56,220,240			# aesenc
.byte	102,15,56,220,248			# aesenc
.byte	102,68,15,56,220,192			# aesenc
.byte	102,68,15,56,220,200			# aesenc
	movups	64-128(%rcx),%xmm0		# Load round key
	bswapl	%r9d				# Byte swap
.byte	102,15,56,220,209			# aesenc
.byte	102,15,56,220,217			# aesenc
	xorl	%ebp,%r9d			# XOR
.byte	0x66,0x90				# NOP
.byte	102,15,56,220,225			# aesenc
.byte	102,15,56,220,233			# aesenc
	movl	%r9d,32+12(%rsp)		# Store counter
	leaq	3(%r8),%r9			# Increment counter
.byte	102,15,56,220,241			# aesenc
.byte	102,15,56,220,249			# aesenc
.byte	102,68,15,56,220,193			# aesenc
.byte	102,68,15,56,220,201			# aesenc
	movups	80-128(%rcx),%xmm1		# Load round key
	bswapl	%r9d				# Byte swap
.byte	102,15,56,220,208			# aesenc
.byte	102,15,56,220,216			# aesenc
	xorl	%ebp,%r9d			# XOR
.byte	0x66,0x90				# NOP
.byte	102,15,56,220,224			# aesenc
.byte	102,15,56,220,232			# aesenc
	movl	%r9d,48+12(%rsp)		# Store counter
	leaq	4(%r8),%r9			# Increment counter
.byte	102,15,56,220,240			# aesenc
.byte	102,15,56,220,248			# aesenc
.byte	102,68,15,56,220,192			# aesenc
.byte	102,68,15,56,220,200			# aesenc
	movups	96-128(%rcx),%xmm0		# Load round key
	bswapl	%r9d				# Byte swap
.byte	102,15,56,220,209			# aesenc
.byte	102,15,56,220,217			# aesenc
	xorl	%ebp,%r9d			# XOR
.byte	0x66,0x90				# NOP
.byte	102,15,56,220,225			# aesenc
.byte	102,15,56,220,233			# aesenc
	movl	%r9d,64+12(%rsp)		# Store counter
	leaq	5(%r8),%r9			# Increment counter
.byte	102,15,56,220,241			# aesenc
.byte	102,15,56,220,249			# aesenc
.byte	102,68,15,56,220,193			# aesenc
.byte	102,68,15,56,220,201			# aesenc
	movups	112-128(%rcx),%xmm1		# Load round key
	bswapl	%r9d				# Byte swap
.byte	102,15,56,220,208			# aesenc
.byte	102,15,56,220,216			# aesenc
	xorl	%ebp,%r9d			# XOR
.byte	0x66,0x90				# NOP
.byte	102,15,56,220,224			# aesenc
.byte	102,15,56,220,232			# aesenc
	movl	%r9d,80+12(%rsp)		# Store counter
	leaq	6(%r8),%r9			# Increment counter
.byte	102,15,56,220,240			# aesenc
.byte	102,15,56,220,248			# aesenc
.byte	102,68,15,56,220,192			# aesenc
.byte	102,68,15,56,220,200			# aesenc
	movups	128-128(%rcx),%xmm0		# Load round key
	bswapl	%r9d				# Byte swap
.byte	102,15,56,220,209			# aesenc
.byte	102,15,56,220,217			# aesenc
	xorl	%ebp,%r9d			# XOR
.byte	0x66,0x90				# NOP
.byte	102,15,56,220,225			# aesenc
.byte	102,15,56,220,233			# aesenc
	movl	%r9d,96+12(%rsp)		# Store counter
	leaq	7(%r8),%r9			# Increment counter
.byte	102,15,56,220,241			# aesenc
.byte	102,15,56,220,249			# aesenc
.byte	102,68,15,56,220,193			# aesenc
.byte	102,68,15,56,220,201			# aesenc
	movups	144-128(%rcx),%xmm1		# Load round key
	bswapl	%r9d				# Byte swap
.byte	102,15,56,220,208			# aesenc
.byte	102,15,56,220,216			# aesenc
.byte	102,15,56,220,224			# aesenc
	xorl	%ebp,%r9d			# XOR
	movdqu	0(%rdi),%xmm10			# Load plaintext
.byte	102,15,56,220,232			# aesenc
	movl	%r9d,112+12(%rsp)		# Store counter
	cmpl	$11,%eax			# Check number of rounds
.byte	102,15,56,220,240			# aesenc
.byte	102,15,56,220,248			# aesenc
.byte	102,68,15,56,220,192			# aesenc
.byte	102,68,15,56,220,200			# aesenc
	movups	160-128(%rcx),%xmm0		# Load round key

	jb	.Lctr32_enc_done		# If less, finish round

.byte	102,15,56,220,209			# aesenc
.byte	102,15,56,220,217			# aesenc
.byte	102,15,56,220,225			# aesenc
.byte	102,15,56,220,233			# aesenc
.byte	102,15,56,220,241			# aesenc
.byte	102,15,56,220,249			# aesenc
.byte	102,68,15,56,220,193			# aesenc
.byte	102,68,15,56,220,201			# aesenc
	movups	176-128(%rcx),%xmm1		# Load round key

.byte	102,15,56,220,208			# aesenc
.byte	102,15,56,220,216			# aesenc
.byte	102,15,56,220,224			# aesenc
.byte	102,15,56,220,232			# aesenc
.byte	102,15,56,220,240			# aesenc
.byte	102,15,56,220,248			# aesenc
.byte	102,68,15,56,220,192			# aesenc
.byte	102,68,15,56,220,200			# aesenc
	movups	192-128(%rcx),%xmm0		# Load round key
	je	.Lctr32_enc_done		# If equal, finish round

.byte	102,15,56,220,209			# aesenc
.byte	102,15,56,220,217			# aesenc
.byte	102,15,56,220,225			# aesenc
.byte	102,15,56,220,233			# aesenc
.byte	102,15,56,220,241			# aesenc
.byte	102,15,56,220,249			# aesenc
.byte	102,68,15,56,220,193			# aesenc
.byte	102,68,15,56,220,201			# aesenc
	movups	208-128(%rcx),%xmm1		# Load round key

.byte	102,15,56,220,208			# aesenc
.byte	102,15,56,220,216			# aesenc
.byte	102,15,56,220,224			# aesenc
.byte	102,15,56,220,232			# aesenc
.byte	102,15,56,220,240			# aesenc
.byte	102,15,56,220,248			# aesenc
.byte	102,68,15,56,220,192			# aesenc
.byte	102,68,15,56,220,200			# aesenc
	movups	224-128(%rcx),%xmm0		# Load round key
	jmp	.Lctr32_enc_done		# Finish round

.align	16					# Align
.Lctr32_enc_done:				# Finalize encryption round
	movdqu	16(%rdi),%xmm11			# Load plaintext
	pxor	%xmm0,%xmm10			# XOR with encrypted counter
	movdqu	32(%rdi),%xmm12
	pxor	%xmm0,%xmm11
	movdqu	48(%rdi),%xmm13
	pxor	%xmm0,%xmm12
	movdqu	64(%rdi),%xmm14
	pxor	%xmm0,%xmm13
	movdqu	80(%rdi),%xmm15
	pxor	%xmm0,%xmm14
	pxor	%xmm0,%xmm15
.byte	102,15,56,220,209			# aesenclast
.byte	102,15,56,220,217			# aesenclast
.byte	102,15,56,220,225			# aesenclast
.byte	102,15,56,220,233			# aesenclast
.byte	102,15,56,220,241			# aesenclast
.byte	102,15,56,220,249			# aesenclast
.byte	102,68,15,56,220,193			# aesenclast
.byte	102,68,15,56,220,201			# aesenclast
	movdqu	96(%rdi),%xmm1			# Load plaintext
	leaq	128(%rdi),%rdi			# Advance input pointer

.byte	102,65,15,56,221,210			# aesenclast
	pxor	%xmm0,%xmm1			# XOR
	movdqu	112-128(%rdi),%xmm10
.byte	102,65,15,56,221,219			# aesenclast
	pxor	%xmm0,%xmm10			# XOR
	movdqa	0(%rsp),%xmm11
.byte	102,65,15,56,221,228			# aesenclast
.byte	102,65,15,56,221,237			# aesenclast
	movdqa	16(%rsp),%xmm12
	movdqa	32(%rsp),%xmm13
.byte	102,65,15,56,221,246			# aesenclast
.byte	102,65,15,56,221,255			# aesenclast
	movdqa	48(%rsp),%xmm14
	movdqa	64(%rsp),%xmm15
.byte	102,68,15,56,221,193			# aesenclast
	movdqa	80(%rsp),%xmm0
	movups	16-128(%rcx),%xmm1
.byte	102,69,15,56,221,202			# aesenclast

	movups	%xmm2,(%rsi)			# Store 8 blocks of ciphertext
	movdqa	%xmm11,%xmm2
	movups	%xmm3,16(%rsi)
	movdqa	%xmm12,%xmm3
	movups	%xmm4,32(%rsi)
	movdqa	%xmm13,%xmm4
	movups	%xmm5,48(%rsi)
	movdqa	%xmm14,%xmm5
	movups	%xmm6,64(%rsi)
	movdqa	%xmm15,%xmm6
	movups	%xmm7,80(%rsi)
	movdqa	%xmm0,%xmm7
	movups	%xmm8,96(%rsi)
	movups	%xmm9,112(%rsi)
	leaq	128(%rsi),%rsi			# Advance output pointer

	subq	$8,%rdx				# Decrement block count
	jnc	.Lctr32_loop8			# Loop if more blocks

	addq	$8,%rdx				# Adjust block count
	jz	.Lctr32_done			# If done, finish
	leaq	-128(%rcx),%rcx			# Adjust key pointer

.Lctr32_tail:					# Handle tail blocks for CTR
	leaq	16(%rcx),%rcx			# Advance key pointer
	cmpq	$4,%rdx				# Compare remaining blocks with 4
	jb	.Lctr32_loop3			# If less, handle <4 blocks
	je	.Lctr32_loop4			# If equal, handle 4 blocks

	shll	$4,%eax				# Calculate key offset
	movdqa	96(%rsp),%xmm8			# Load counter state
	pxor	%xmm9,%xmm9			# Zero register

	movups	16(%rcx),%xmm0			# Load round key
.byte	102,15,56,220,209			# aesenc
.byte	102,15,56,220,217			# aesenc
	leaq	32-16(%rcx,%rax,1),%rcx		# Calculate end of key schedule
	negq	%rax				# Negate offset
.byte	102,15,56,220,225			# aesenc
	addq	$16,%rax				# Adjust offset
	movups	(%rdi),%xmm10			# Load plaintext
.byte	102,15,56,220,233			# aesenc
.byte	102,15,56,220,241			# aesenc
	movups	16(%rdi),%xmm11
	movups	32(%rdi),%xmm12
.byte	102,15,56,220,249			# aesenc
.byte	102,68,15,56,220,193			# aesenc

	call	.Lenc_loop8_enter		# Call encryption loop

	movdqu	48(%rdi),%xmm13			# Load plaintext
	pxor	%xmm10,%xmm2			# XOR with encrypted counter
	movdqu	64(%rdi),%xmm10
	pxor	%xmm11,%xmm3
	movdqu	%xmm2,(%rsi)			# Store ciphertext
	pxor	%xmm12,%xmm4
	movdqu	%xmm3,16(%rsi)
	pxor	%xmm13,%xmm5
	movdqu	%xmm4,32(%rsi)
	pxor	%xmm10,%xmm6
	movdqu	%xmm5,48(%rsi)
	movdqu	%xmm6,64(%rsi)
	cmpq	$6,%rdx				# Compare with 6
	jb	.Lctr32_done			# If less, finish

	movups	80(%rdi),%xmm11			# Load plaintext
	xorps	%xmm11,%xmm7			# XOR
	movups	%xmm7,80(%rsi)			# Store ciphertext
	je	.Lctr32_done			# If done, finish

	movups	96(%rdi),%xmm12			# Load plaintext
	xorps	%xmm12,%xmm8			# XOR
	movups	%xmm8,96(%rsi)			# Store ciphertext
	jmp	.Lctr32_done			# Finish

.align	32					# Align
.Lctr32_loop4:					# 4-block CTR loop
.byte	102,15,56,220,209			# aesenc
	leaq	16(%rcx),%rcx			# Advance key pointer
	decl	%eax				# Decrement round counter
.byte	102,15,56,220,217			# aesenc
.byte	102,15,56,220,225			# aesenc
.byte	102,15,56,220,233			# aesenc
	movups	(%rcx),%xmm1			# Load round key
	jnz	.Lctr32_loop4			# Loop
.byte	102,15,56,221,209			# aesenclast
.byte	102,15,56,221,217			# aesenclast
	movups	(%rdi),%xmm10			# Load plaintext
	movups	16(%rdi),%xmm11
.byte	102,15,56,221,225			# aesenclast
.byte	102,15,56,221,233			# aesenclast
	movups	32(%rdi),%xmm12
	movups	48(%rdi),%xmm13

	xorps	%xmm10,%xmm2			# XOR and store ciphertext
	movups	%xmm2,(%rsi)
	xorps	%xmm11,%xmm3
	movups	%xmm3,16(%rsi)
	pxor	%xmm12,%xmm4
	movdqu	%xmm4,32(%rsi)
	pxor	%xmm13,%xmm5
	movdqu	%xmm5,48(%rsi)
	jmp	.Lctr32_done			# Finish

.align	32					# Align
.Lctr32_loop3:					# 3-block CTR loop
.byte	102,15,56,220,209			# aesenc
	leaq	16(%rcx),%rcx			# Advance key pointer
	decl	%eax				# Decrement round counter
.byte	102,15,56,220,217			# aesenc
.byte	102,15,56,220,225			# aesenc
	movups	(%rcx),%xmm1			# Load round key
	jnz	.Lctr32_loop3			# Loop
.byte	102,15,56,221,209			# aesenclast
.byte	102,15,56,221,217			# aesenclast
.byte	102,15,56,221,225			# aesenclast

	movups	(%rdi),%xmm10			# Load plaintext
	xorps	%xmm10,%xmm2			# XOR and store
	movups	%xmm2,(%rsi)
	cmpq	$2,%rdx				# Compare with 2
	jb	.Lctr32_done			# If less, finish

	movups	16(%rdi),%xmm11			# Load plaintext
	xorps	%xmm11,%xmm3			# XOR and store
	movups	%xmm3,16(%rsi)
	je	.Lctr32_done			# If done, finish

	movups	32(%rdi),%xmm12			# Load plaintext
	xorps	%xmm12,%xmm4			# XOR and store
	movups	%xmm4,32(%rsi)

.Lctr32_done:					# Cleanup for CTR
	xorps	%xmm0,%xmm0			# Clear registers
	xorl	%ebp,%ebp
	pxor	%xmm1,%xmm1
	pxor	%xmm2,%xmm2
	pxor	%xmm3,%xmm3
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	pxor	%xmm6,%xmm6
	pxor	%xmm7,%xmm7
	movaps	%xmm0,0(%rsp)
	pxor	%xmm8,%xmm8
	movaps	%xmm0,16(%rsp)
	pxor	%xmm9,%xmm9
	movaps	%xmm0,32(%rsp)
	pxor	%xmm10,%xmm10
	movaps	%xmm0,48(%rsp)
	pxor	%xmm11,%xmm11
	movaps	%xmm0,64(%rsp)
	pxor	%xmm12,%xmm12
	movaps	%xmm0,80(%rsp)
	pxor	%xmm13,%xmm13
	movaps	%xmm0,96(%rsp)
	pxor	%xmm14,%xmm14
	movaps	%xmm0,112(%rsp)
	pxor	%xmm15,%xmm15
	movq	-8(%r11),%rbp			# Restore base pointer
.cfi_restore	%rbp
	leaq	(%r11),%rsp			# Restore stack pointer
.cfi_def_cfa_register	%rsp
.Lctr32_epilogue:				# Epilogue for CTR
	.byte	0xf3,0xc3				# rep ret: Return
.cfi_endproc					# CFI end
.size	snts_aesni_ctr32_encrypt_blocks,.-snts_aesni_ctr32_encrypt_blocks	# Set function size

# Function: snts_aesni_set_decrypt_key
# Sets up the AES decryption key schedule.
.globl	snts_aesni_set_decrypt_key		# Make visible to linker
.type	snts_aesni_set_decrypt_key,@function	# Define as function
.align	16					# Align to 16-byte boundary
snts_aesni_set_decrypt_key:			# Function label
.cfi_startproc					# CFI start
.byte	0x48,0x83,0xEC,0x08			# sub $8, %rsp
.cfi_adjust_cfa_offset	8
	call	__snts_aesni_set_encrypt_key	# Call encrypt key setup first
	shll	$4,%esi				# Calculate key schedule size
	testl	%eax,%eax			# Check return value
	jnz	.Ldec_key_ret			# If error, return
	leaq	16(%rdx,%rsi,1),%rdi		# Calculate end of key schedule

	movups	(%rdx),%xmm0			# Load first round key
	movups	(%rdi),%xmm1			# Load last round key
	movups	%xmm0,(%rdi)			# Swap them
	movups	%xmm1,(%rdx)
	leaq	16(%rdx),%rdx			# Advance pointers
	leaq	-16(%rdi),%rdi

.Ldec_key_inverse:				# Loop to apply Inverse Mix Columns
	movups	(%rdx),%xmm0			# Load round key
	movups	(%rdi),%xmm1			# Load round key
.byte	102,15,56,219,192			# aesimc %xmm0, %xmm0
.byte	102,15,56,219,201			# aesimc %xmm1, %xmm1
	leaq	16(%rdx),%rdx			# Advance pointers
	leaq	-16(%rdi),%rdi
	movups	%xmm0,16(%rdi)			# Store transformed keys
	movups	%xmm1,-16(%rdx)
	cmpq	%rdx,%rdi			# Compare pointers
	ja	.Ldec_key_inverse		# Loop if not done

	movups	(%rdx),%xmm0			# Load middle key
.byte	102,15,56,219,192			# aesimc %xmm0, %xmm0
	pxor	%xmm1,%xmm1			# Clear register
	movups	%xmm0,(%rdi)			# Store transformed key
	pxor	%xmm0,%xmm0			# Clear register
.Ldec_key_ret:					# Return point
	addq	$8,%rsp				# Restore stack
.cfi_adjust_cfa_offset	-8
	.byte	0xf3,0xc3				# rep ret: Return
.cfi_endproc					# CFI end
.LSEH_end_set_decrypt_key:
.size	snts_aesni_set_decrypt_key,.-snts_aesni_set_decrypt_key	# Set function size

# Function: snts_aesni_set_encrypt_key
# Sets up the AES encryption key schedule.
.globl	snts_aesni_set_encrypt_key		# Make visible to linker
.type	snts_aesni_set_encrypt_key,@function	# Define as function
.align	16					# Align to 16-byte boundary
snts_aesni_set_encrypt_key:			# Function label
__snts_aesni_set_encrypt_key:			# Internal entry point
.cfi_startproc					# CFI start
.byte	0x48,0x83,0xEC,0x08			# sub $8, %rsp
.cfi_adjust_cfa_offset	8
	movq	$-1,%rax			# Set return value to -1 (error)
	testq	%rdi,%rdi			# Check for null key pointer
	jz	.Lenc_key_ret			# If null, return
	testq	%rdx,%rdx			# Check for null schedule pointer
	jz	.Lenc_key_ret			# If null, return

	movl	$268437504,%r10d		# Load capability flags mask
	movups	(%rdi),%xmm0			# Load user key
	xorps	%xmm4,%xmm4			# Zero register
	andl	_OPENSSL_ia32cap_P+4(%rip),%r10d	# Check for AES-NI and VAES support
	leaq	16(%rdx),%rax			# Point to second round key slot
	cmpl	$256,%esi			# Compare key size with 256
	je	.L14rounds			# If 256, jump to 14 rounds
	cmpl	$192,%esi			# Compare key size with 192
	je	.L12rounds			# If 192, jump to 12 rounds
	cmpl	$128,%esi			# Compare key size with 128
	jne	.Lbad_keybits			# If not 128, error

.L10rounds:					# Key expansion for 128-bit key
	movl	$9,%esi				# Set number of rounds
	cmpl	$268435456,%r10d		# Check for VAES support
	je	.L10rounds_alt			# If so, use alternate path

	movups	%xmm0,(%rdx)			# Store first round key
.byte	102,15,58,223,200,1			#aeskeygenassist $0x1, %xmm0, %xmm1
	call	.Lkey_expansion_128_cold	# Expand key
.byte	102,15,58,223,200,2			#aeskeygenassist $0x2, %xmm0, %xmm1
	call	.Lkey_expansion_128		# Expand key
.byte	102,15,58,223,200,4			#aeskeygenassist $0x4, %xmm0, %xmm1
	call	.Lkey_expansion_128		# Expand key
.byte	102,15,58,223,200,8			#aeskeygenassist $0x8, %xmm0, %xmm1
	call	.Lkey_expansion_128		# Expand key
.byte	102,15,58,223,200,16			#aeskeygenassist $0x10, %xmm0, %xmm1
	call	.Lkey_expansion_128		# Expand key
.byte	102,15,58,223,200,32			#aeskeygenassist $0x20, %xmm0, %xmm1
	call	.Lkey_expansion_128		# Expand key
.byte	102,15,58,223,200,64			#aeskeygenassist $0x40, %xmm0, %xmm1
	call	.Lkey_expansion_128		# Expand key
.byte	102,15,58,223,200,128			#aeskeygenassist $0x80, %xmm0, %xmm1
	call	.Lkey_expansion_128		# Expand key
.byte	102,15,58,223,200,27			#aeskeygenassist $0x1b, %xmm0, %xmm1
	call	.Lkey_expansion_128		# Expand key
.byte	102,15,58,223,200,54			#aeskeygenassist $0x36, %xmm0, %xmm1
	call	.Lkey_expansion_128		# Expand key
	movups	%xmm0,(%rax)			# Store final round key
	movl	%esi,80(%rax)			# Store number of rounds
	xorl	%eax,%eax			# Set return value to 0 (success)
	jmp	.Lenc_key_ret			# Return

.align	16					# Align
.L10rounds_alt:					# Alternate path for 128-bit key (VAES)
	movdqa	.Lkey_rotate(%rip),%xmm5		# Load rotation mask
	movl	$8,%r10d			# Set loop counter
	movdqa	.Lkey_rcon1(%rip),%xmm4		# Load RCON value
	movdqa	%xmm0,%xmm2			# Copy key
	movdqu	%xmm0,(%rdx)			# Store first round key
	jmp	.Loop_key128			# Jump to loop

.align	16					# Align
.Loop_key128:					# Loop for 128-bit key expansion
.byte	102,15,56,0,197				# pshufb %xmm5, %xmm1
.byte	102,15,56,221,196			# pshufd $0xff, %xmm0, %xmm4
	pslld	$1,%xmm4			# Shift RCON
	leaq	16(%rax),%rax			# Advance schedule pointer

	movdqa	%xmm2,%xmm3			# Copy key
	pslldq	$4,%xmm2			# Shift
	pxor	%xmm2,%xmm3			# XOR
	pslldq	$4,%xmm2			# Shift
	pxor	%xmm2,%xmm3			# XOR
	pslldq	$4,%xmm2			# Shift
	pxor	%xmm3,%xmm2			# XOR

	pxor	%xmm2,%xmm0			# XOR to generate next key
	movdqu	%xmm0,-16(%rax)			# Store round key
	movdqa	%xmm0,%xmm2			# Copy key

	decl	%r10d				# Decrement loop counter
	jnz	.Loop_key128			# Loop

	movdqa	.Lkey_rcon1b(%rip),%xmm4		# Load RCON value

.byte	102,15,56,0,197				# pshufb %xmm5, %xmm1
.byte	102,15,56,221,196			# pshufd $0xff, %xmm0, %xmm4
	pslld	$1,%xmm4			# Shift RCON

	movdqa	%xmm2,%xmm3			# Copy key
	pslldq	$4,%xmm2			# Shift
	pxor	%xmm2,%xmm3			# XOR
	pslldq	$4,%xmm2			# Shift
	pxor	%xmm2,%xmm3			# XOR
	pslldq	$4,%xmm2			# Shift
	pxor	%xmm3,%xmm2			# XOR

	pxor	%xmm2,%xmm0			# XOR to generate next key
	movdqu	%xmm0,(%rax)			# Store round key

	movdqa	%xmm0,%xmm2			# Copy key
.byte	102,15,56,0,197				# pshufb %xmm5, %xmm1
.byte	102,15,56,221,196			# pshufd $0xff, %xmm0, %xmm4

	movdqa	%xmm2,%xmm3			# Copy key
	pslldq	$4,%xmm2			# Shift
	pxor	%xmm2,%xmm3			# XOR
	pslldq	$4,%xmm2			# Shift
	pxor	%xmm2,%xmm3			# XOR
	pslldq	$4,%xmm2			# Shift
	pxor	%xmm3,%xmm2			# XOR

	pxor	%xmm2,%xmm0			# XOR to generate next key
	movdqu	%xmm0,16(%rax)			# Store round key

	movl	%esi,96(%rax)			# Store number of rounds
	xorl	%eax,%eax			# Set return value to 0
	jmp	.Lenc_key_ret			# Return

.align	16					# Align
.L12rounds:					# Key expansion for 192-bit key
	movq	16(%rdi),%xmm2			# Load second part of key
	movl	$11,%esi			# Set number of rounds
	cmpl	$268435456,%r10d		# Check for VAES
	je	.L12rounds_alt			# If so, use alternate path

	movups	%xmm0,(%rdx)			# Store first part of key
.byte	102,15,58,223,202,1			#aeskeygenassist $0x1, %xmm2, %xmm1
	call	.Lkey_expansion_192a_cold	# Expand key
.byte	102,15,58,223,202,2			#aeskeygenassist $0x2, %xmm2, %xmm1
	call	.Lkey_expansion_192b		# Expand key
.byte	102,15,58,223,202,4			#aeskeygenassist $0x4, %xmm2, %xmm1
	call	.Lkey_expansion_192a		# Expand key
.byte	102,15,58,223,202,8			#aeskeygenassist $0x8, %xmm2, %xmm1
	call	.Lkey_expansion_192b		# Expand key
.byte	102,15,58,223,202,16			#aeskeygenassist $0x10, %xmm2, %xmm1
	call	.Lkey_expansion_192a		# Expand key
.byte	102,15,58,223,202,32			#aeskeygenassist $0x20, %xmm2, %xmm1
	call	.Lkey_expansion_192b		# Expand key
.byte	102,15,58,223,202,64			#aeskeygenassist $0x40, %xmm2, %xmm1
	call	.Lkey_expansion_192a		# Expand key
.byte	102,15,58,223,202,128			#aeskeygenassist $0x80, %xmm2, %xmm1
	call	.Lkey_expansion_192b		# Expand key
	movups	%xmm0,(%rax)			# Store final round key
	movl	%esi,48(%rax)			# Store number of rounds
	xorq	%rax,%rax			# Set return value to 0
	jmp	.Lenc_key_ret			# Return

.align	16					# Align
.L12rounds_alt:					# Alternate path for 192-bit key (VAES)
	movdqa	.Lkey_rotate192(%rip),%xmm5	# Load rotation mask
	movdqa	.Lkey_rcon1(%rip),%xmm4		# Load RCON value
	movl	$8,%r10d			# Set loop counter
	movdqu	%xmm0,(%rdx)			# Store first part of key
	jmp	.Loop_key192			# Jump to loop

.align	16					# Align
.Loop_key192:					# Loop for 192-bit key expansion
	movq	%xmm2,0(%rax)			# Store part of key
	movdqa	%xmm2,%xmm1			# Copy key
.byte	102,15,56,0,213				# pshufb %xmm5, %xmm1
.byte	102,15,56,221,212			# pshufd $0xff, %xmm0, %xmm4
	pslld	$1,%xmm4			# Shift RCON
	leaq	24(%rax),%rax			# Advance schedule pointer

	movdqa	%xmm0,%xmm3			# Copy key
	pslldq	$4,%xmm0			# Shift
	pxor	%xmm0,%xmm3			# XOR
	pslldq	$4,%xmm0			# Shift
	pxor	%xmm0,%xmm3			# XOR
	pslldq	$4,%xmm0			# Shift
	pxor	%xmm3,%xmm0			# XOR

	pshufd	$0xff,%xmm0,%xmm3		# Shuffle
	pxor	%xmm1,%xmm3			# XOR
	pslldq	$4,%xmm1			# Shift
	pxor	%xmm1,%xmm3			# XOR

	pxor	%xmm2,%xmm0			# XOR to generate next key
	pxor	%xmm3,%xmm2			# XOR
	movdqu	%xmm0,-16(%rax)			# Store round key

	decl	%r10d				# Decrement loop counter
	jnz	.Loop_key192			# Loop

	movl	%esi,32(%rax)			# Store number of rounds
	xorl	%eax,%eax			# Set return value to 0
	jmp	.Lenc_key_ret			# Return

.align	16					# Align
.L14rounds:					# Key expansion for 256-bit key
	movups	16(%rdi),%xmm2			# Load second part of key
	movl	$13,%esi			# Set number of rounds
	leaq	16(%rax),%rax			# Advance schedule pointer
	cmpl	$268435456,%r10d		# Check for VAES
	je	.L14rounds_alt			# If so, use alternate path

	movups	%xmm0,(%rdx)			# Store first part of key
	movups	%xmm2,16(%rdx)			# Store second part of key
.byte	102,15,58,223,202,1			#aeskeygenassist $0x1, %xmm2, %xmm1
	call	.Lkey_expansion_256a_cold	# Expand key
.byte	102,15,58,223,200,1			#aeskeygenassist $0x1, %xmm0, %xmm1
	call	.Lkey_expansion_256b		# Expand key
.byte	102,15,58,223,202,2			#aeskeygenassist $0x2, %xmm2, %xmm1
	call	.Lkey_expansion_256a		# Expand key
.byte	102,15,58,223,200,2			#aeskeygenassist $0x2, %xmm0, %xmm1
	call	.Lkey_expansion_256b		# Expand key
.byte	102,15,58,223,202,4			#aeskeygenassist $0x4, %xmm2, %xmm1
	call	.Lkey_expansion_256a		# Expand key
.byte	102,15,58,223,200,4			#aeskeygenassist $0x4, %xmm0, %xmm1
	call	.Lkey_expansion_256b		# Expand key
.byte	102,15,58,223,202,8			#aeskeygenassist $0x8, %xmm2, %xmm1
	call	.Lkey_expansion_256a		# Expand key
.byte	102,15,58,223,200,8			#aeskeygenassist $0x8, %xmm0, %xmm1
	call	.Lkey_expansion_256b		# Expand key
.byte	102,15,58,223,202,16			#aeskeygenassist $0x10, %xmm2, %xmm1
	call	.Lkey_expansion_256a		# Expand key
.byte	102,15,58,223,200,16			#aeskeygenassist $0x10, %xmm0, %xmm1
	call	.Lkey_expansion_256b		# Expand key
.byte	102,15,58,223,202,32			#aeskeygenassist $0x20, %xmm2, %xmm1
	call	.Lkey_expansion_256a		# Expand key
.byte	102,15,58,223,200,32			#aeskeygenassist $0x20, %xmm0, %xmm1
	call	.Lkey_expansion_256b		# Expand key
.byte	102,15,58,223,202,64			#aeskeygenassist $0x40, %xmm2, %xmm1
	call	.Lkey_expansion_256a		# Expand key
	movups	%xmm0,(%rax)			# Store final round key
	movl	%esi,16(%rax)			# Store number of rounds
	xorq	%rax,%rax			# Set return value to 0
	jmp	.Lenc_key_ret			# Return

.align	16					# Align
.L14rounds_alt:					# Alternate path for 256-bit key (VAES)
	movdqa	.Lkey_rotate(%rip),%xmm5		# Load rotation mask
	movdqa	.Lkey_rcon1(%rip),%xmm4		# Load RCON value
	movl	$7,%r10d			# Set loop counter
	movdqu	%xmm0,0(%rdx)			# Store first part of key
	movdqa	%xmm2,%xmm1			# Copy key
	movdqu	%xmm2,16(%rdx)			# Store second part of key
	jmp	.Loop_key256			# Jump to loop

.align	16					# Align
.Loop_key256:					# Loop for 256-bit key expansion
.byte	102,15,56,0,213				# pshufb %xmm5, %xmm1
.byte	102,15,56,221,212			# pshufd $0xff, %xmm0, %xmm4

	movdqa	%xmm0,%xmm3			# Copy key
	pslldq	$4,%xmm0			# Shift
	pxor	%xmm0,%xmm3			# XOR
	pslldq	$4,%xmm0			# Shift
	pxor	%xmm0,%xmm3			# XOR
	pslldq	$4,%xmm0			# Shift
	pxor	%xmm3,%xmm0			# XOR
	pslld	$1,%xmm4			# Shift RCON

	pxor	%xmm2,%xmm0			# XOR to generate next key
	movdqu	%xmm0,(%rax)			# Store round key

	decl	%r10d				# Decrement loop counter
	jz	.Ldone_key256			# If done, finish

	pshufd	$0xff,%xmm0,%xmm2		# Shuffle
	pxor	%xmm3,%xmm3			# Zero register
.byte	102,15,56,221,211			# pshufd $0xaa, %xmm1, %xmm3

	movdqa	%xmm1,%xmm3			# Copy key
	pslldq	$4,%xmm1			# Shift
	pxor	%xmm1,%xmm3			# XOR
	pslldq	$4,%xmm1			# Shift
	pxor	%xmm1,%xmm3			# XOR
	pslldq	$4,%xmm1			# Shift
	pxor	%xmm3,%xmm1			# XOR

	pxor	%xmm1,%xmm2			# XOR to generate next key
	movdqu	%xmm2,16(%rax)			# Store round key
	leaq	32(%rax),%rax			# Advance schedule pointer
	movdqa	%xmm2,%xmm1			# Copy key

	jmp	.Loop_key256			# Loop

.Ldone_key256:					# Finish 256-bit key expansion
	movl	%esi,16(%rax)			# Store number of rounds
	xorl	%eax,%eax			# Set return value to 0
	jmp	.Lenc_key_ret			# Return

.align	16					# Align
.Lbad_keybits:					# Error handling for invalid key size
	movq	$-2,%rax			# Set return value to -2
.Lenc_key_ret:					# Return point for key setup
	pxor	%xmm0,%xmm0			# Clear registers
	pxor	%xmm1,%xmm1
	pxor	%xmm2,%xmm2
	pxor	%xmm3,%xmm3
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	addq	$8,%rsp				# Restore stack
.cfi_adjust_cfa_offset	-8
	.byte	0xf3,0xc3				# rep ret: Return
.LSEH_end_set_encrypt_key:

.align	16					# Align
.Lkey_expansion_128:				# Helper for 128-bit key expansion
	movups	%xmm0,(%rax)			# Store round key
	leaq	16(%rax),%rax			# Advance pointer
.Lkey_expansion_128_cold:			# Cold path entry
	shufps	$16,%xmm0,%xmm4			# Shuffle
	xorps	%xmm4,%xmm0			# XOR
	shufps	$140,%xmm0,%xmm4			# Shuffle
	xorps	%xmm4,%xmm0			# XOR
	shufps	$255,%xmm1,%xmm1			# Shuffle
	xorps	%xmm1,%xmm0			# XOR
	.byte	0xf3,0xc3				# rep ret: Return

.align	16					# Align
.Lkey_expansion_192a:				# Helper for 192-bit key expansion (part a)
	movups	%xmm0,(%rax)			# Store round key
	leaq	16(%rax),%rax			# Advance pointer
.Lkey_expansion_192a_cold:			# Cold path entry
	movaps	%xmm2,%xmm5			# Copy key
.Lkey_expansion_192b_warm:			# Warm path entry
	shufps	$16,%xmm0,%xmm4			# Shuffle
	movdqa	%xmm2,%xmm3			# Copy key
	xorps	%xmm4,%xmm0			# XOR
	shufps	$140,%xmm0,%xmm4			# Shuffle
	pslldq	$4,%xmm3			# Shift
	xorps	%xmm4,%xmm0			# XOR
	pshufd	$85,%xmm1,%xmm1			# Shuffle
	pxor	%xmm3,%xmm2			# XOR
	pxor	%xmm1,%xmm0			# XOR
	pshufd	$255,%xmm0,%xmm3		# Shuffle
	pxor	%xmm3,%xmm2			# XOR
	.byte	0xf3,0xc3				# rep ret: Return

.align	16					# Align
.Lkey_expansion_192b:				# Helper for 192-bit key expansion (part b)
	movaps	%xmm0,%xmm3			# Copy key
	shufps	$68,%xmm0,%xmm5			# Shuffle
	movups	%xmm5,(%rax)			# Store round key
	shufps	$78,%xmm2,%xmm3			# Shuffle
	movups	%xmm3,16(%rax)			# Store round key
	leaq	32(%rax),%rax			# Advance pointer
	jmp	.Lkey_expansion_192b_warm	# Jump to warm path

.align	16					# Align
.Lkey_expansion_256a:				# Helper for 256-bit key expansion (part a)
	movups	%xmm2,(%rax)			# Store round key
	leaq	16(%rax),%rax			# Advance pointer
.Lkey_expansion_256a_cold:			# Cold path entry
	shufps	$16,%xmm0,%xmm4			# Shuffle
	xorps	%xmm4,%xmm0			# XOR
	shufps	$140,%xmm0,%xmm4			# Shuffle
	xorps	%xmm4,%xmm0			# XOR
	shufps	$255,%xmm1,%xmm1			# Shuffle
	xorps	%xmm1,%xmm0			# XOR
	.byte	0xf3,0xc3				# rep ret: Return

.align	16					# Align
.Lkey_expansion_256b:				# Helper for 256-bit key expansion (part b)
	movups	%xmm0,(%rax)			# Store round key
	leaq	16(%rax),%rax			# Advance pointer

	shufps	$16,%xmm2,%xmm4			# Shuffle
	xorps	%xmm4,%xmm2			# XOR
	shufps	$140,%xmm2,%xmm4			# Shuffle
	xorps	%xmm4,%xmm2			# XOR
	shufps	$170,%xmm1,%xmm1			# Shuffle
	xorps	%xmm1,%xmm2			# XOR
	.byte	0xf3,0xc3				# rep ret: Return
.cfi_endproc					# CFI end
.size	snts_aesni_set_encrypt_key,.-snts_aesni_set_encrypt_key	# Set function size
.size	__snts_aesni_set_encrypt_key,.-__snts_aesni_set_encrypt_key	# Set function size

# Data section with constants
.align	64					# Align to 64-byte boundary
.Lbswap_mask:					# Mask for byte swapping
.byte	15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
.Lincrement32:					# 32-bit increment value
.long	6,6,6,0
.Lincrement64:					# 64-bit increment value
.long	1,0,0,0
.Lxts_magic:					# Magic value for XTS mode
.long	0x87,0,1,0
.Lincrement1:					# 1-byte increment value
.byte	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
.Lkey_rotate:					# Rotation mask for key expansion
.long	0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d
.Lkey_rotate192:				# Rotation mask for 192-bit key expansion
.long	0x04070605,0x04070605,0x04070605,0x04070605
.Lkey_rcon1:					# RCON constant for key expansion
.long	1,1,1,1
.Lkey_rcon1b:					# RCON constant for key expansion
.long	0x1b,0x1b,0x1b,0x1b

# Informational string
.byte	65,69,83,32,102,111,114,32,73,110,116,101,108,32,65,69,83,45,78,73,44,32,67,82,89,80,84,79,71,65,77,83,32,98,121,32,60,97,112,112,114,111,64,111,112,101,110,115,115,108,46,111,114,103,62,0
.align	64					# Align to 64-byte boundary

# GNU property note section for specifying architecture features
	.section ".note.gnu.property", "a"
	.p2align 3
	.long 1f - 0f
	.long 4f - 1f
	.long 5
0:
	# "GNU" encoded with .byte, since .asciz isn't supported
	# on Solaris.
	.byte 0x47
	.byte 0x4e
	.byte 0x55
	.byte 0
1:
	.p2align 3
	.long 0xc0000002
	.long 3f - 2f
2:
	.long 3
3:
	.p2align 3
4:

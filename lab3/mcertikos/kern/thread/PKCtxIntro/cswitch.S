/*
 * void cswitch(struct kctx *from, struct kctx *to);
 */
	.globl cswitch
cswitch:
	movl	4(%esp), %eax	/* %eax <- from */
	movl	8(%esp), %edx	/* %edx <- to */

	/* TODO: save the old kernel context */
	movl	0(%esp), %ecx
	movl	%ecx, 20(%eax)
	movl	%ebp, 16(%eax)
	movl	%ebx, 12(%eax)
	movl	%esi, 8(%eax)
	movl	%edi, 4(%eax)
	movl	%esp, 0(%eax)

	/* TODO: load the new kernel context */
	movl	0(%edx), %esp
	movl	4(%edx), %edi
	movl	8(%edx), %esi
	movl	12(%edx), %ebx
	movl	16(%edx), %ebp
	movl	20(%edx), %ecx
	movl	%ecx, 0(%esp)

	xor	%eax, %eax
	ret


/*
Here's a brief overview of these x86 registers:

esp: Stack Pointer – points to the top of the current stack frame, used to track function calls.
ecx: Counter Register – often used as a loop counter or for shift/rotate operations.
ebp: Base Pointer – points to the base of the current stack frame, helping manage local variables in functions.
ebx: Base Register – a general-purpose register, often used for data storage.
esi: Source Index – typically used in memory copying operations as the source address.
edi: Destination Index – usually used in memory copying operations as the destination address.
edx: Data Register – another general-purpose register, often used to hold data or for division/multiplication.

*/
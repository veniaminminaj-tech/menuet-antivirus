;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;   AVTEST64 - Antivirus Test module for Menuet64
;
;   Compile with FASM (1.73.x), e.g.:  fasm avtest64.asm AVTEST64
;   STATUS: NOT COMPILED OR RUN. Verify the build before relying on it.
;
;   What it does:
;     1. Deletes old test files (ignores errors).
;     2. Writes two harmless test files to TEST_DIR:
;          EICAR.COM   - standard EICAR antivirus test string (68 bytes)
;          SIGNAT.TXT  - benign text marker, not a signature for any malware
;     3. Reads each file back with syscall 58/0 and compares the bytes.
;     4. Shows WRITE/READ result per file in the window.
;
;   IMPORTANT LIMITATION:
;     MenuetOS syscalls.txt documents no antivirus API. This program cannot
;     see an AV verdict. "DETECTED" or "MISSED" must be checked by the
;     antivirus outside this program, e.g. by scanning the test disk image
;     or the test folder from the host, or by the AV running in the VM.
;     This module only proves the files were created and are intact.
;
;   Filesystem note (from syscalls.txt, syscall 58):
;     rbx=0 read, rbx=1 write (only creates new files; error 16 if exists),
;     rbx=2 delete, r9 = asciiz path. Directories are not created here.
;     Create TEST_DIR yourself on the dedicated test disk before running.
;
;   Safety: writes only the two fixed file names below. No execution of
;   test files. No persistence, no hiding, no self-copy.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

use64

    org   0x0

    db    'MENUET64'              ; Header identifier
    dq    0x01                    ; Version
    dq    START                   ; Start of code
    dq    image_end               ; Size of image
    dq    0x100000                ; Memory for app
    dq    0xffff0                 ; Rsp
    dq    0x00                    ; Prm
    dq    0x00                    ; Icon


START:

    call  run_tests               ; Run tests once at start
    call  draw_window

still:

    mov   rax , 10                ; Wait for event
    int   0x60

    test  rax , 1                 ; Window redraw
    jnz   window_event
    test  rax , 2                 ; Keyboard press
    jnz   key_event
    test  rax , 4                 ; Button press
    jnz   button_event

    jmp   still

window_event:

    call  draw_window
    jmp   still

key_event:

    mov   rax , 2                 ; Read and ignore key
    int   0x60
    jmp   still

button_event:

    mov   rax , 17                ; Get button id
    int   0x60

    cmp   rbx , 0x10000001        ; No buttons are defined; kept for future Quit button
    jne   still
    mov   rax , 0x200             ; Terminate process
    int   0x60


; ---------------------------------------------------------------
; run_tests: delete, write, read back and verify both test files
; ---------------------------------------------------------------
run_tests:

    ; --- test 1: EICAR ---
    mov   qword [cur_name] , name_eicar
    mov   qword [cur_data] , eicar_string
    mov   qword [cur_len]  , eicar_len
    call  write_and_verify
    mov   [res_eicar] , rax       ; 0 ok, 1 write fail, 2 read fail, 3 mismatch

    ; --- test 2: benign marker ---
    mov   qword [cur_name] , name_sig
    mov   qword [cur_data] , sig_string
    mov   qword [cur_len]  , sig_len
    call  write_and_verify
    mov   [res_sig] , rax

    ret


; ---------------------------------------------------------------
; write_and_verify
;   in : cur_name (asciiz path), cur_data (bytes), cur_len (count)
;   out: rax = 0 ok, 1 write failed, 2 read failed, 3 mismatch
; ---------------------------------------------------------------
write_and_verify:

    ; delete old copy (result ignored: file may not exist)
    mov   rax , 58
    mov   rbx , 2
    mov   r9  , [cur_name]
    int   0x60

    ; write new file
    mov   rax , 58
    mov   rbx , 1
    mov   rdx , [cur_len]         ; bytes to save
    mov   r8  , [cur_data]        ; pointer to data
    mov   r9  , [cur_name]        ; filename
    int   0x60
    test  rax , rax
    jnz   .write_fail

    ; read back: first 512-byte block
    mov   rax , 58
    mov   rbx , 0
    mov   rcx , 0                 ; first block
    mov   rdx , 1                 ; one block
    mov   r8  , read_buffer       ; return pointer
    mov   r9  , [cur_name]
    int   0x60
    test  rax , rax
    jnz   .read_fail

    ; rbx = file size returned by read; must equal what we wrote
    cmp   rbx , [cur_len]
    jne   .mismatch

    ; byte compare
    mov   rsi , [cur_data]
    mov   rdi , read_buffer
    mov   rcx , [cur_len]
    repe  cmpsb
    jne   .mismatch

    xor   rax , rax               ; success
    ret

  .write_fail:
    mov   rax , 1
    ret
  .read_fail:
    mov   rax , 2
    ret
  .mismatch:
    mov   rax , 3
    ret


; ---------------------------------------------------------------
; draw_window: show results
; ---------------------------------------------------------------
draw_window:

    mov   rax , 12                ; Begin window draw
    mov   rbx , 1
    int   0x60

    mov   rax , 0x0               ; Draw window
    mov   rbx , 200 shl 32 + 340  ; X start & size
    mov   rcx , 150 shl 32 + 170  ; Y start & size
    mov   rdx , 0x0000000000FFFFFF
    mov   r8  , 0x0000000000000001
    mov   r9  , window_label
    mov   r10 , 0
    int   0x60

    ; line 1: EICAR result
    mov   rax , 4
    mov   rbx , line_eicar_prefix
    mov   rcx , 16
    mov   rdx , 40
    mov   rsi , 0x000000
    mov   r9  , 1
    int   0x60
    mov   rax , 4
    mov   rbx , status_table
    mov   rdx , [res_eicar]
    shl   rdx , 3
    add   rbx , rdx
    mov   rbx , [rbx]             ; pointer to status string
    mov   rcx , 16 + 8*12
    mov   rdx , 40
    mov   rsi , 0x000000
    mov   r9  , 1
    int   0x60

    ; line 2: signature result
    mov   rax , 4
    mov   rbx , line_sig_prefix
    mov   rcx , 16
    mov   rdx , 64
    mov   rsi , 0x000000
    mov   r9  , 1
    int   0x60
    mov   rax , 4
    mov   rbx , status_table
    mov   rdx , [res_sig]
    shl   rdx , 3
    add   rbx , rdx
    mov   rbx , [rbx]
    mov   rcx , 16 + 8*12
    mov   rdx , 64
    mov   rsi , 0x000000
    mov   r9  , 1
    int   0x60

    ; line 3: note
    mov   rax , 4
    mov   rbx , line_note
    mov   rcx , 16
    mov   rdx , 96
    mov   rsi , 0x000000
    mov   r9  , 1
    int   0x60

    ; line 4: note 2
    mov   rax , 4
    mov   rbx , line_note2
    mov   rcx , 16
    mov   rdx , 112
    mov   rsi , 0x000000
    mov   r9  , 1
    int   0x60

    mov   rax , 12                ; End window draw
    mov   rbx , 2
    int   0x60

    ret


; ---------------------------------------------------------------
; Data
; ---------------------------------------------------------------

; NOTE: change TEST_DIR to a folder on your dedicated test disk.
; Paths are examples, not verified to exist on every setup.
name_eicar:
    db    '/fd/1/EICAR.COM',0
name_sig:
    db    '/fd/1/SIGNAT.TXT',0

; Standard EICAR antivirus test file (68 bytes, harmless text).
eicar_string:
    db    'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
eicar_len = $ - eicar_string

; Benign marker, not a malware signature.
sig_string:
    db    'ANTIVIRUS_TEST_SIGNATURE_BENIGN_0001',13,10
sig_len = $ - sig_string

window_label:
    db    'AVTEST64',0

line_eicar_prefix:
    db    'EICAR file:',0
line_sig_prefix:
    db    'Marker file:',0
line_note:
    db    'Scan TEST files with AV on host or VM.',0
line_note2:
    db    'AV verdict is not visible to this app.',0

st_ok:
    db    'WRITE+READ OK',0
st_wfail:
    db    'ERROR write',0
st_rfail:
    db    'ERROR read',0
st_mismatch:
    db    'ERROR mismatch',0

status_table:
    dq    st_ok, st_wfail, st_rfail, st_mismatch

; Variables
cur_name:     dq 0
cur_data:     dq 0
cur_len:      dq 0
res_eicar:    dq 0
res_sig:      dq 0

read_buffer:  db 512 dup 0    ; emitted zeros, so image_end matches the file

image_end:

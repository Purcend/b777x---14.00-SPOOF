/*
 * GoldHEN payload - partial reverse-engineered by b777x <3 
 * Guys You Shouldn't Be Gatekeeping Still ... PS4 TIME
 *
 * IMPORTANT:
 *   This is NOT the original GoldHEN source code. Names/types were inferred.
 *   It preserves the observable control flow of selected loader, also helps you find any firmware as a spoofer if ur smart :)
 */

#include <stdint.h>
#include <stddef.h>

/* Parsed from the kernel's release string. */
static uint16_t cached_fw;

/*
 * The payload obtains the kernel base from IA32_LSTAR (MSR 0xC0000082)
 * and subtracts 0x1c0 from the syscall entry address.
 */
static uintptr_t get_kernel_base_from_lstar(void) {
    /* pseudocode only:
       uint64_t lstar = rdmsr(0xC0000082);
       return (uintptr_t)(lstar - 0x1c0);
    */
    return 0;
}

/*
 * Reconstructed from the routine at binary offset 0xE90.
 * It scans a kernel-memory window for the ASCII marker "s/release_"
 * and converts four decimal digits around it into the integer format
 * used by the dispatch code (e.g. 13.52 -> 1352).
 */
static uint16_t detect_firmware(void) {
    if (cached_fw != 0)
        return cached_fw;

    uintptr_t kbase = get_kernel_base_from_lstar();
    const char marker[10] = {'s','/','r','e','l','e','a','s','e','_'};

    /* Observed scan window in the binary:
       start = kbase + 0x01300000
       end   = kbase + 0x02200000
       The exact surrounding data structure is inferred.
    */

    /* When marker is found, digits are weighted as:
       d0*1000 + d1*100 + d2*10 + d3
       giving values such as 505, 900, 1100, 1300, 1352.
    */
    return cached_fw;
}

/*
 * Firmware families observed in the dispatch routine at 0x14A6/0x16E8.
 * Some comparisons intentionally group neighboring revisions.
 */
static int firmware_is_supported(uint16_t fw) {
    switch (fw) {
        case 505: case 507:
        case 671: case 672:
        case 700: case 701: case 702:
        case 750: case 751: case 755:
        case 800: case 801: case 803:
        case 850: case 852:
        case 900: case 903: case 904:
        case 950: case 951: case 960:
        case 1000: case 1001:
        case 1050:
        case 1070: case 1071:
        case 1100: case 1102:
        case 1150: case 1152:
        case 1200:
        case 1250: case 1252:
        case 1300:
        case 1352:
            return 1;
        default:
            return 0;
    }
}

/*
 * The real payload has two closely related firmware-dispatch functions.
 * Each chooses a firmware-specific offset/patch table builder.
 * Addresses below are binary offsets of the called routines, useful for
 * continuing analysis in Ghidra/IDA/radare2.
 */
struct fw_dispatch_entry {
    uint16_t fw;
    uint32_t routine_a;
    uint32_t routine_b;
};

static const struct fw_dispatch_entry dispatch_map[] = {
    { 505, 0x37C1, 0x355A },
    { 671, 0x3A51, 0x37EA },
    { 672, 0x3CE1, 0x3A7A },
    { 700, 0x3F71, 0x3D0A }, /* grouped 700-702 */
    { 750, 0x4201, 0x3F9A },
    { 751, 0x4491, 0x422A },
    { 755, 0x4721, 0x44BA },
    { 800, 0x49B1, 0x474A },
    { 801, 0x4C41, 0x49DA },
    { 803, 0x4ED1, 0x4C6A },
    { 850, 0x5161, 0x4EFA },
    { 852, 0x53F1, 0x518A },
    { 900, 0x5681, 0x541A },
    { 903, 0x5911, 0x56AA },
    { 904, 0x5BA1, 0x593A },
    { 950, 0x5E31, 0x5BCA },
    { 951, 0x60C1, 0x5E5A },
    { 960, 0x6351, 0x60EA },
    {1000, 0x1B91, 0x192A },
    {1001, 0x1E21, 0x1BBA },
    {1050, 0x20B1, 0x1E4A },
    {1070, 0x2341, 0x20DA }, /* grouped 1070-1071 */
    {1100, 0x25D1, 0x236A },
    {1102, 0x2861, 0x25FA },
    {1150, 0x2AF1, 0x288A }, /* grouped 1150/1152 */
    {1200, 0x2D81, 0x2B1A },
    {1250, 0x3011, 0x2DAA }, /* grouped 1250/1252 */
    {1300, 0x32A1, 0x303A },
    {1352, 0x3531, 0x32CA },
};

/* Entry point at file offset 0x0000 jumps to 0x0E3B.
 * The code there validates the caller/context, then invokes a raw syscall
 * helper at 0x0E6B and proceeds into kernel-side setup.
 */
static int payload_entry(void *arg) {
    (void)arg;
    /* exact body not yet fully decompiled */
    return 0;
}

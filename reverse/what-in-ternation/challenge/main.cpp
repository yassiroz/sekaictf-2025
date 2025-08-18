#include "inttypes.h"
#include "stdio.h"
#include "string.h"
#include <immintrin.h>

__m512i int_to_vec(uint64_t x) { return _mm512_movm_epi8(x); }

[[gnu::noinline]] __m512i program(__m512i char_input_a, __m512i char_input_b,
                                  __m512i char_input_c, __m512i char_input_d,
                                  __m512i char_input_e, __m512i char_input_f,
                                  __m512i char_input_g, __m512i char_input_h) {
#include "program.cpp"
  return is_correct;
}

[[gnu::noinline]] bool evaluate(char *flag) {
  uint64_t *input = (uint64_t *)flag;
  __m512i char_input_a = int_to_vec(input[0]);
  __m512i char_input_b = int_to_vec(input[1]);
  __m512i char_input_c = int_to_vec(input[2]);
  __m512i char_input_d = int_to_vec(input[3]);
  __m512i char_input_e = int_to_vec(input[4]);
  __m512i char_input_f = int_to_vec(input[5]);
  __m512i char_input_g = int_to_vec(input[6]);
  __m512i char_input_h = int_to_vec(input[7]);

  __m512i is_correct =
      program(char_input_a, char_input_b, char_input_c, char_input_d,
              char_input_e, char_input_f, char_input_g, char_input_h);

  // extract bottom bit of `is_correct`
  int result = _mm_extract_epi8(_mm512_castsi512_si128(is_correct), 0);
  return (result & 1) != 0;
}

int main(int argc, char *argv[]) {
  // check if AVX512_VBMI is supported
  if (!__builtin_cpu_supports("avx512vbmi")) {
    puts("Your computer no hablo AVX512-VBMI. If you're on a recent Intel CPU, "
         "you might be able to enable it in the BIOS (at the cost of disabling "
         "your efficiency cores). Otherwise, try finding a teammate with a Zen "
         "4/5 CPU, or grab a quick VM on a cloud provider that supports "
         "AVX512-VBMI.");
    return 1;
  }

  if (argc != 2) {
    puts("Usage: ./what-in-ternation <flag>");
    return 1;
  }

  if (strlen(argv[1]) == 64 && evaluate(argv[1])) {
    puts("Yep!");
  } else {
    puts("Nope.");
  }

  return 0;
}
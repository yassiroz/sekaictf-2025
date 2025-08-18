module flag_checker(
    input wire [63:0] char_input_a,
    input wire [63:0] char_input_b,
    input wire [63:0] char_input_c,
    input wire [63:0] char_input_d,
    input wire [63:0] char_input_e,
    input wire [63:0] char_input_f,
    input wire [63:0] char_input_g,
    input wire [63:0] char_input_h,

    output wire         is_correct
);
    // check whether given character is valid
    function automatic is_char_valid(input [7:0] char);
        is_char_valid = ( ((char >= "a") && (char <= "z")) ||
                          ((char >= "A") && (char <= "Z")) ||
                          ((char >= "0") && (char <= "9")) ||
                          (char == "_") || (char == "{") || (char == "}") );
    endfunction
      
    wire [511:0] all_inputs = {char_input_h, char_input_g, char_input_f, char_input_e,
                               char_input_d, char_input_c, char_input_b, char_input_a};
    wire [63:0] input_range_check;
      
    genvar i;
    generate
        for (i = 0; i < 64; i = i + 1) begin: char_validator
            assign input_range_check[i] = is_char_valid(all_inputs[(i*8)+7 : i*8]);
        end
    endgenerate
      
    // next, check each chunk of 8 characters in order
    wire [7:0] chunk_check;

    assign chunk_check[0] = char_input_a == "5a{IAKES";
    assign chunk_check[1] = (char_input_b ^ char_input_d) == 64'h0831001044092934;
    assign chunk_check[2] = (char_input_c[7:0] == char_input_b[31:24]) && (char_input_c[15:8] == char_input_h[7:0]) && (char_input_c[23:16] == char_input_d[31:24]) && (char_input_c[31:24] == char_input_e[7:0]) && (char_input_c[39:32] == char_input_b[47:40]) && (char_input_c[47:40] == char_input_b[15:8]) && (char_input_c[55:48] == char_input_e[39:32]) && (char_input_c[63:56] == char_input_f[47:40]);
    assign chunk_check[3] = (char_input_d ^ 64'hb5d34b5f62469ec7) == 64'hd9bd393a1636e898;
    assign chunk_check[4] = ~char_input_e == 64'h8da08ccea09b9890;
    assign chunk_check[5] = (char_input_f ^ char_input_h) == 64'h0f03573b400e5552;

    wire [63:0] g_lo_res;
    assign g_lo_res = char_input_g[31:0] * 32'h92236a43;
    wire [63:0] g_hi_res;
    assign g_hi_res = char_input_g[63:32] * 32'ha2ae904c;
    assign chunk_check[6] = g_lo_res == 64'h42e5db7d83ee19dd && g_hi_res == 64'h2314adbd7786fc34;

    assign chunk_check[7] = char_input_h == "}31d4f2c";

    assign is_correct = &input_range_check // all characters must be valid
                        && &chunk_check;   // and all chunks must match expected values
endmodule

module bitcoin_hash1(input logic clk, reset_n, start,
								input logic [15:0] message_addr, output_addr,
								output logic done, mem_clk, mem_we,
								output logic [15:0] mem_addr,
								output logic [31:0] mem_write_data,
								input logic [31:0] mem_read_data
								);


	// SHA256 K constants
	parameter int k[0:63] = '{
		32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
		32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
		32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
		32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
		32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
		32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
		32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
		32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
	};
	
	parameter NUM_NONCES = 16;
	
	logic[15:0] t; //Processing rounds counter
	logic[31:0] H[8]; //Array of all current H values for the current nonce
	logic[31:0] w[16]; //holds most recent 16 words
	logic [31:0] a, b, c, d, e, f, g, h;
	logic [4:0] writeCounter;
	logic [31:0] s0, s1;
	logic [15:0] read_addr, write_addr; 
	enum logic [3:0] {IDLE,READ0,READ1,READBLOCK1,READBLOCK2,EXPAND,COMPUTE,WRITE,PREPAREPHASE3,SAVEPHASE3} state;
	enum logic [1:0] {FIRSTBLOCK, SECONDBLOCK} blockNum;
	
	
	
	
	logic	[4:0] nonceCounter = 0;
	logic [2:0] phasenum = 1;
	
	
	logic   [31:0] h0[NUM_NONCES];
	logic   [31:0] h1[NUM_NONCES];
	logic   [31:0] h2[NUM_NONCES];
	logic   [31:0] h3[NUM_NONCES];
	logic   [31:0] h4[NUM_NONCES];
	logic   [31:0] h5[NUM_NONCES];
	logic   [31:0] h6[NUM_NONCES];
	logic   [31:0] h7[NUM_NONCES];
	
	
	logic[31:0] block2Words[3];
	
	logic[31:0] fh[8];
	

	//right rotate function in lecture 11
	function logic [31:0] rightrotate(input logic [31:0] x,
												input logic [7:0] r);
		rightrotate = (x >> r) | (x << (32-r));
	endfunction
	
	//wtnew function in lecture 12
	function logic [31:0] wtnew; // function with no inputs
		logic [31:0] s0, s1;
		
		s0 = rightrotate(w[1],7)^rightrotate(w[1],18)^(w[1]>>3);
		s1 = rightrotate(w[14],17)^rightrotate(w[14],19)^(w[14]>>10);
		wtnew = w[0] + s0 + w[9] + s1;
	endfunction


	// SHA256 hash round
	function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
												input logic [7:0] t);
		 logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
	begin
		 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
		 ch = (e & f) ^ ((~e) & g);
		 t1 = h + S1 + ch + k[t] + w;
		 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
		 maj = (a & b) ^ (a & c) ^ (b & c);
		 t2 = S0 + maj;

		 sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
	end
	endfunction								
									
	assign mem_clk = clk;
	
	
	always_ff @(posedge clk, negedge reset_n) begin
		if(!reset_n) begin
			blockNum <= FIRSTBLOCK;
			state <= IDLE;
		end else case(state)
			IDLE: begin
				writeCounter <= 0;
				mem_we <= 0;
				t <= 0;
				H[0] = 32'h6a09e667;
				H[1] = 32'hbb67ae85;
				H[2] = 32'h3c6ef372;
				H[3] = 32'ha54ff53a;
				H[4] = 32'h510e527f;
				H[5] = 32'h9b05688c;
				H[6] = 32'h1f83d9ab;
				H[7] = 32'h5be0cd19;
				a = 32'h6a09e667;
				b = 32'hbb67ae85;
				c = 32'h3c6ef372;
				d = 32'ha54ff53a;
				e = 32'h510e527f;
				f = 32'h9b05688c;
				g = 32'h1f83d9ab;
				h = 32'h5be0cd19;
				
				if(start)begin
					done <= 0;
					mem_addr <= message_addr;
					read_addr <= message_addr + 1;
					state <= READ0;
				end
			end
			READ0: begin
				mem_addr <= read_addr;
				read_addr <= read_addr+1;
				state <= READBLOCK1;
				if(blockNum == SECONDBLOCK)begin
					mem_addr <= message_addr + 16;
					read_addr <= message_addr + 17;
					state <= READ1;
				end
			end
			READ1: begin
				mem_addr <= read_addr;
				read_addr <= read_addr+1;
				state <= READBLOCK2;
			end
			READBLOCK1: begin
				if(t < 15)begin
					mem_addr <= read_addr;
					read_addr <= read_addr+1;
					mem_we <= 0;
					w[t] <= mem_read_data;
					t <= t+1;
					state <= READBLOCK1;
				end
				else begin
					read_addr <= read_addr-1;
					mem_we <= 0;
					w[t] <= mem_read_data;
					blockNum <= FIRSTBLOCK;
					t <= 0;
					state <= COMPUTE;
					
				end
			end
			READBLOCK2:begin
				if(t < 3 && nonceCounter == 0)begin
					mem_addr <= read_addr;
					read_addr <= read_addr+1;
					mem_we <= 0;
					w[t] <= mem_read_data;
					block2Words[t] <= mem_read_data;
					t <= t+1;
					state <= READBLOCK2;
				end
				else begin
				
					if(nonceCounter!=0)begin
						w[0] = block2Words[0];
						w[1] = block2Words[1];
						w[2] = block2Words[2];
						
						H[0] <= fh[0];
						H[1] <= fh[1];
						H[2] <= fh[2];
						H[3] <= fh[3];
						H[4] <= fh[4];
						H[5] <= fh[5];
						H[6] <= fh[6];
						H[7] <= fh[7];
						
						
				
					end
	
						a <= fh[0];
						b <= fh[1];
						c <= fh[2];
						d <= fh[3];
						e <= fh[4];
						f <= fh[5];
						g <= fh[6];
						h <= fh[7];
	
	
					w[3]				<= nonceCounter;
					w[4]				<= 32'h80000000;
					w[5]		 		<= 32'h00000000;
					w[6]		 		<= 32'h00000000;
					w[7]		 		<= 32'h00000000;
					w[8]		 		<= 32'h00000000;
					w[9]		 		<= 32'h00000000;
					w[10]		 		<= 32'h00000000;
					w[11]		 		<= 32'h00000000;
					w[12]		 		<= 32'h00000000;
					w[13]		 		<= 32'h00000000;
					w[14]		 		<= 32'h00000000;
					w[15] 			<= 32'd640;
					t <= 0;
					blockNum <= SECONDBLOCK;
					phasenum <= 2;
					state <= COMPUTE;
					

				end			
			end
			COMPUTE:begin
			
				if(t<15)begin
					{a, b, c, d, e, f, g, h} = sha256_op(a, b, c, d, e, f, g, h, w[t], t);
					t <= t+1;
					state <= COMPUTE;
				end else if (t<64)begin
					for (int n = 0; n < 15; n++) w[n] <= w[n+1];
					w[15] <= wtnew();
					{a, b, c, d, e, f, g, h} = sha256_op(a, b, c, d, e, f, g, h, w[15], t);
					t <= t+1;
					
					
				end else begin
					H[0] = H[0] + a;
					H[1] = H[1] + b;
					H[2] = H[2] + c;
					H[3] = H[3] + d;
					H[4] = H[4] + e;
					H[5] = H[5] + f;
					H[6] = H[6] + g;
					H[7] = H[7] + h;
					t <= 0;
					if(blockNum <= FIRSTBLOCK)begin
					//double check
						fh[0] = H[0];
						fh[1] = H[1];
						fh[2] = H[2];
						fh[3] = H[3];
						fh[4] = H[4];
						fh[5] = H[5];
						fh[6] = H[6];
						fh[7] = H[7];
						t <= 0;
						phasenum <= 2;
						blockNum <= SECONDBLOCK;
						state <= READ0;
					end else if(phasenum<=2) begin
						//go to phase 3 if currently in phase 2
						phasenum <= 3;
						state <= PREPAREPHASE3;//phase 3
					end
					else begin
						state <= SAVEPHASE3;
					end
				end
			end
			
			PREPAREPHASE3:begin
				w[0] = H[0];
				w[1] = H[1];
				w[2] = H[2];
				w[3] = H[3];
				w[4] = H[4];
				w[5] = H[5];
				w[6] = H[6];
				w[7] = H[7];
				w[8]				<= 32'h80000000;
				w[9]		 		<= 32'h00000000;
				w[10]		 		<= 32'h00000000;
				w[11]		 		<= 32'h00000000;
				w[12]		 		<= 32'h00000000;
				w[13]		 		<= 32'h00000000;
				w[14]		 		<= 32'h00000000;
				w[15] 			<= 32'd256;
			
			
			
				H[0] = 32'h6a09e667;
				H[1] = 32'hbb67ae85;
				H[2] = 32'h3c6ef372;
				H[3] = 32'ha54ff53a;
				H[4] = 32'h510e527f;
				H[5] = 32'h9b05688c;
				H[6] = 32'h1f83d9ab;
				H[7] = 32'h5be0cd19;
				a = 32'h6a09e667;
				b = 32'hbb67ae85;
				c = 32'h3c6ef372;
				d = 32'ha54ff53a;
				e = 32'h510e527f;
				f = 32'h9b05688c;
				g = 32'h1f83d9ab;
				h = 32'h5be0cd19;
				
				state <= COMPUTE;
			
			end
			
			
			SAVEPHASE3:begin
				h0[nonceCounter] <= H[0];
				h1[nonceCounter] <= H[1];
				h2[nonceCounter] <= H[2];
				h3[nonceCounter] <= H[3];
				h4[nonceCounter] <= H[4];
				h5[nonceCounter] <= H[5];
				h6[nonceCounter] <= H[6];
				h7[nonceCounter] <= H[7];
			
				if(nonceCounter == 15)begin
					state <= WRITE;
				end
				else begin
					phasenum <= 2;
					nonceCounter++;
					state <= READBLOCK2;
				end
			
			
			end
			
			
			
			WRITE: begin
				
				mem_we <= 1;
				if(writeCounter == 16)begin
					done <= 1;
					state <= IDLE;
				end else
				begin
					mem_addr <= output_addr + writeCounter;
					mem_write_data <= h0[writeCounter];
					writeCounter <= writeCounter + 1;
					state <= WRITE;
				end
			
			end
			
			
		endcase
	
	end
	

endmodule



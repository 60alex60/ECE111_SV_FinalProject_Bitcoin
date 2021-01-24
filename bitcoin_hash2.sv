
module bitcoin_hash2(input logic clk, reset_n, start,
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
	logic[31:0] H[NUM_NONCES][8]; //Array of all current H values for the current nonce
	logic[31:0] w[NUM_NONCES][16]; //holds most recent 16 words
	logic [31:0] a[NUM_NONCES], b[NUM_NONCES], c[NUM_NONCES], d[NUM_NONCES], e[NUM_NONCES], f[NUM_NONCES], g[NUM_NONCES], h[NUM_NONCES];
	logic [4:0] writeCounter, loopCounter;
	logic [31:0] s0, s1;
	logic [15:0] read_addr, write_addr; 
	enum logic [3:0] {IDLE,READ0,READ1,READBLOCK1,READBLOCK2,COMPUTE,WRITE,PREPAREPHASE3} state;
	enum logic [1:0] {FIRSTBLOCK, SECONDBLOCK} blockNum;
	
	
	logic [2:0] phasenum = 1;
	
	
	logic[31:0] block2Words[3];
	
	logic[31:0] fh[8];
	
	logic [4:0] wtInput; 
	logic [31:0] shaInput = 0;
	logic [31:0] shaInputArr [NUM_NONCES];
	
	logic   [31:0] dv0  = 32'h6a09e667;
	logic   [31:0] dv1  = 32'hbb67ae85;
	logic   [31:0] dv2 = 32'h3c6ef372;
	logic   [31:0] dv3 = 32'ha54ff53a;
	logic   [31:0] dv4 = 32'h510e527f;
	logic   [31:0] dv5 = 32'h9b05688c;
	logic   [31:0] dv6 = 32'h1f83d9ab;
	logic   [31:0] dv7 = 32'h5be0cd19;
	
	logic [31:0] zero = 32'h00000000;
	logic [31:0] eight = 32'h80000000;
	
	
/*	int computeP1 = 0;
	int computeP2 = 0;
	int computeP3 = 0;
*/	

	//right rotate function in lecture 11
	function logic [31:0] rightrotate(input logic [31:0] x,
												input logic [7:0] r);
		rightrotate = (x >> r) | (x << (32-r));
	endfunction
	
	//wtnew function in lecture 12
	function logic [31:0] wtnew (); // function with no inputs
		logic [31:0] s0, s1;
		
		s0 = rightrotate(w[wtInput][1],7)^rightrotate(w[wtInput][1],18)^(w[wtInput][1]>>3);
		s1 = rightrotate(w[wtInput][14],17)^rightrotate(w[wtInput][14],19)^(w[wtInput][14]>>10);
		wtnew = w[wtInput][0] + s0 + w[wtInput][9] + s1;
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
			
				
				if(start)begin
					writeCounter <= 0;
					mem_we <= 0;
					t <= 0;
					H[0][0] = dv0;
					H[0][1] = dv1;
					H[0][2] = dv2;
					H[0][3] = dv3;
					H[0][4] = dv4;
					H[0][5] = dv5;
					H[0][6] = dv6;
					H[0][7] = dv7;
					a[0] = dv0;
					b[0] = dv1;
					c[0] = dv2;
					d[0] = dv3;
					e[0] = dv4;
					f[0] = dv5;
					g[0] = dv6;
					h[0] = dv7;
				
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
					w[0][t] <= mem_read_data;
					t <= t+1;
					state <= READBLOCK1;
				end
				else begin
					read_addr <= read_addr-1;
					mem_we <= 0;
					w[0][t] <= mem_read_data;
					blockNum <= FIRSTBLOCK;
					t <= 0;
					
//new					
					shaInput <= w[0][0];
					
					state <= COMPUTE;
					
				end
			end
			READBLOCK2:begin
				if(t < 3)begin
					mem_addr <= read_addr;
					read_addr <= read_addr+1;
					mem_we <= 0;
					w[0][t] <= mem_read_data;
					block2Words[t] <= mem_read_data;
					t <= t+1;
					state <= READBLOCK2;
				end
				else begin
				
						
						
						for (int i = 0; i<NUM_NONCES; i++)begin
							a[i] <= fh[0];
							b[i] <= fh[1];
							c[i] <= fh[2];
							d[i] <= fh[3];
							e[i] <= fh[4];
							f[i] <= fh[5];
							g[i] <= fh[6];
							h[i] <= fh[7];
							
		//CHECK TODO
							shaInputArr[i] = block2Words[0];
							w[i][0] = block2Words[0];
							w[i][1] = block2Words[1];
							w[i][2] = block2Words[2];
							
							H[i][0] <= fh[0];
							H[i][1] <= fh[1];
							H[i][2] <= fh[2];
							H[i][3] <= fh[3];
							H[i][4] <= fh[4];
							H[i][5] <= fh[5];
							H[i][6] <= fh[6];
							H[i][7] <= fh[7];
							
							w[i][3]				<= i;
							w[i][4]				<= eight;
							w[i][5]		 		<= zero;
							w[i][6]		 		<= zero;
							w[i][7]		 		<= zero;
							w[i][8]		 		<= zero;
							w[i][9]		 		<= zero;
							w[i][10]		 		<= zero;
							w[i][11]		 		<= zero;
							w[i][12]		 		<= zero;
							w[i][13]		 		<= zero;
							w[i][14]		 		<= zero;
							w[i][15] 			<= 32'd640;
							
						end
						
					
			
					t <= 0;
					blockNum <= SECONDBLOCK;
					phasenum <= 2;
					
					state <= COMPUTE;
					

				end			
			end
			COMPUTE:begin
				if(blockNum == FIRSTBLOCK)begin
				
				
		//			$display("ComputeP1: %d",computeP1++);
				
					
					{a[0], b[0], c[0], d[0], e[0], f[0], g[0], h[0]} = sha256_op(a[0], b[0], c[0], d[0], e[0], f[0], g[0], h[0], shaInput, t);
					
					
					
					
					if(t<14)begin
						shaInput = w[0][t+1];
						t <= t+1;
						state <= COMPUTE;
					end else if (t<63)begin
						for (int n = 0; n < 15; n++) w[0][n] <= w[0][n+1];
						wtInput = 0;
						w[0][15] <= wtnew();
						shaInput = w[0][15];
						t <= t+1;
						state <= COMPUTE;
					
					
					
					end else begin
						H[0][0] = H[0][0] + a[0];
						H[0][1] = H[0][1] + b[0];
						H[0][2] = H[0][2] + c[0];
						H[0][3] = H[0][3] + d[0];
						H[0][4] = H[0][4] + e[0];
						H[0][5] = H[0][5] + f[0];
						H[0][6] = H[0][6] + g[0];
						H[0][7] = H[0][7] + h[0];
						t <= 0;
						
						//double check
						fh[0] = H[0][0];
						fh[1] = H[0][1];
						fh[2] = H[0][2];
						fh[3] = H[0][3];
						fh[4] = H[0][4];
						fh[5] = H[0][5];
						fh[6] = H[0][6];
						fh[7] = H[0][7];
						t <= 0;
						phasenum <= 2;
						blockNum <= SECONDBLOCK;
						state <= READ0;
					end
					
				end else begin
			
	//				if(phasenum==2) $display("ComputeP2: %d",computeP2++);
	//				if(phasenum==3) $display("ComputeP3: %d",computeP3++);
				
				
					for (int i = 0; i<NUM_NONCES; i++) begin	

						{a[i], b[i], c[i], d[i], e[i], f[i], g[i], h[i]} = sha256_op(a[i], b[i], c[i], d[i], e[i], f[i], g[i], h[i], shaInputArr[i], t);
					end
					
					
					
					if(t<14)begin
						for (int i = 0; i<NUM_NONCES; i++) begin	
							shaInputArr[i] = w[i][t+1];
						end
						t <= t+1;
						state <= COMPUTE;
					end else if (t<63)begin
						for (int i = 0; i<NUM_NONCES; i++) begin	
							
							
							for (int n = 0; n < 15; n++) w[i][n] <= w[i][n+1];
							wtInput = i;
							w[i][15] <= wtnew();
							shaInputArr[i] = w[i][15];
							
							
						end
						t <= t+1;
						state <= COMPUTE;	
						
						
						
						
						
			
					end else begin
						for (int i = 0; i<NUM_NONCES; i++) begin
							H[i][0] = H[i][0] + a[i];
							H[i][1] = H[i][1] + b[i];
							H[i][2] = H[i][2] + c[i];
							H[i][3] = H[i][3] + d[i];
							H[i][4] = H[i][4] + e[i];
							H[i][5] = H[i][5] + f[i];
							H[i][6] = H[i][6] + g[i];
							H[i][7] = H[i][7] + h[i];
						end	
						t <= 0;
						
						
						state <= WRITE;
						
						if(phasenum==2) begin
							//go to phase 3 if currently in phase 2
							phasenum <= 3;
							state <= PREPAREPHASE3;//phase 3
						end 
					end
				end
			end
			
			PREPAREPHASE3:begin
			
			
			
				//$display("Prep Phase 3");
			
				for (int i = 0; i<NUM_NONCES; i++) begin
	//CHECK TODO					
					shaInputArr[i] = H[i][0];
					w[i][0] = H[i][0];
					w[i][1] = H[i][1];
					w[i][2] = H[i][2];
					w[i][3] = H[i][3];
					w[i][4] = H[i][4];
					w[i][5] = H[i][5];
					w[i][6] = H[i][6];
					w[i][7] = H[i][7];
					w[i][8]				<= eight;
					w[i][9]		 		<= zero;
					w[i][10]		 		<= zero;
					w[i][11]		 		<= zero;
					w[i][12]		 		<= zero;
					w[i][13]		 		<= zero;
					w[i][14]		 		<= zero;
					w[i][15] 			<= 32'd256;
				
				
				
					H[i][0] = dv0;
					H[i][1] = dv1;
					H[i][2] = dv2;
					H[i][3] = dv3;
					H[i][4] = dv4;
					H[i][5] = dv5;
					H[i][6] = dv6;
					H[i][7] = dv7;
					a[i] = dv0;
					b[i] = dv1;
					c[i] = dv2;
					d[i] = dv3;
					e[i] = dv4;
					f[i] = dv5;
					g[i] = dv6;
					h[i] = dv7;
				end

				state <= COMPUTE;
			
			end
			
			
			
			
			WRITE: begin
				
				mem_we <= 1;
				if(writeCounter == 16)begin
					done <= 1;
					state <= IDLE;
				end else
				begin
					mem_addr <= output_addr + writeCounter;
					mem_write_data <= H[writeCounter][0];
					writeCounter <= writeCounter + 1;
					state <= WRITE;
				end
			
			end
			
			
		endcase
	
	end
	

endmodule



!function(exports) {

	var crypto = exports.crypto || (exports.crypto = {});

	/* aditional crypto functions */

	function arrtohex(arr) { // array to hex
		for (var i = arr.length; i--;) arr[i] = ("0000000"+(arr[i]>>>0).toString(16)).slice(-8);
		return arr.join("");
	}

	function strtoarr(str) { // string to array
		var s = unescape(encodeURIComponent(str));
		var len = s.length;
		var i = 0;
		var bin = [];

		for (; i < len;) {
			bin[i>>2] = s.charCodeAt(i++)<<24 |
				s.charCodeAt(i++)<<16 |
				s.charCodeAt(i++)<<8 |
				s.charCodeAt(i++)
		}
		bin.len = len
		return bin
	}

	/* HMAC */

	function hmac(secret, data) {
		var hasher = sha256;
		var i = 0;
		var ipad = [];
		var opad = [];
		var key = (secret.length > 64 ? hasher : strtoarr)(secret);
		var txt = typeof data == "string" ? strtoarr(data) : data
		var len = txt.len || txt.length * 4;
		

		for (; i < 16;) {
			ipad[i] = key[i]^0x36363636
			opad[i] = key[i++]^0x5c5c5c5c
		}

		return hasher(opad.concat(hasher(ipad.concat(txt), 64 + len)));
	}

	


	/* SHA256 */

	function shaInit(bin, len) {
		if (typeof bin == "string") {
			bin = strtoarr(bin);
			len = bin.len;
		} else len = len || bin.length<<2

		bin[len>>2] |= 0x80 << (24 - (31 & (len<<=3)))
		bin[((len + 64 >> 9) << 4) + 15] = len;

		return bin;
	}

	var initial_map = [];
	var constants_map = [];

	function shaMaps() {
		// getFractionalBits
		function a(e) {
			return (e - (e>>>0)) * 0x100000000 | 0;
		}

		outer: for (var b = 0, c = 2, d; b < 64; c++) {
			// isPrime
			for (d = 2; d * d <= c; d++) if (c % d === 0) continue outer;
			if (b < 8) initial_map[b] = a(Math.pow(c, .5));
			constants_map[b++] = a(Math.pow(c, 1 / 3));
		}
	}

	function sha256(data, binlen) {
		initial_map[0] || shaMaps();

		var a, b, c, d, e, f, g, h, t1, t2, j;
		var i = 0;
		var w = [];
		var A = initial_map[0];
		var B = initial_map[1];
		var C = initial_map[2];
		var D = initial_map[3];
		var E = initial_map[4];
		var F = initial_map[5];
		var G = initial_map[6];
		var H = initial_map[7];
		var bin = shaInit(data, binlen);
		var len = bin.length;
		var K = constants_map;


		for (; i < len; ) {
			a = A;
			b = B;
			c = C;
			d = D;
			e = E;
			f = F;
			g = G;
			h = H;

			for (j = 0; j < 64; ) {
				if (j < 16) {
					w[j] = bin[i+j];
				} else {
					t1 = w[j-2];
					t2 = w[j-15];
					w[j] = (t1>>>17^t1<<15^t1>>>19^t1<<13^t1>>>10) + (w[j-7]|0) + (t2>>>7^t2<<25^t2>>>18^t2<<14^t2>>>3) + (w[j-16]|0);
				}

				t1 = (w[j]|0) + h + (e>>>6^e<<26^e>>>11^e<<21^e>>>25^e<<7) + ((e&f)^((~e)&g)) + K[j++];
				t2 = (a>>>2^a<<30^a>>>13^a<<19^a>>>22^a<<10) + ((a&b)^(a&c)^(b&c));

				h = g;
				g = f;
				f = e;
				e = (d + t1)|0;
				d = c;
				c = b;
				b = a;
				a = (t1 + t2)|0;
			}
			A += a;
			B += b;
			C += c;
			D += d;
			E += e;
			F += f;
			G += g;
			H += h;
			i += 16;
		}
		return [A, B, C, D, E, F, G, H];
	}


	crypto.hmac = function(secret, data) {
		return arrtohex(hmac(secret, data));
	}
	crypto.sha256 = function(data) {
		return arrtohex(sha256(data));
	}


}(this);





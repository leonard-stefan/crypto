# Crypto

A lightweight, pure js crypto library for sha256 and hmac.

## How to use it

```html
<script type="text/javascript" src="crypto.js"></script>
<script>

	/* should return: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 */
	const sha256 = crypto.sha256("hello");

	/* should return: 88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b */
	const hmac = crypto.hmac("secret","hello");

</script>
```



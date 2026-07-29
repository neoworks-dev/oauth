//#region src/vault/api.ts
var UnauthorizedError = class extends Error {
	constructor() {
		super("vault: no usable access token for the API");
		this.name = "UnauthorizedError";
	}
};
var ApiClient = class {
	constructor(options) {
		this.options = options;
	}
	async request(method, path, body) {
		const token = this.options.getToken();
		if (!token) throw new UnauthorizedError();
		const response = await this.send(method, path, token, body);
		if (response.status !== 401) return response;
		const refreshed = await this.options.refreshToken();
		if (!refreshed) throw new UnauthorizedError();
		return this.send(method, path, refreshed, body);
	}
	async json(method, path, body) {
		const response = await this.request(method, path, body);
		if (!response.ok) throw new Error(`${method} ${path} failed: ${response.status}`);
		return await response.json();
	}
	send(method, path, token, body) {
		const headers = { Authorization: `Bearer ${token}` };
		if (body !== void 0) headers["Content-Type"] = "application/json";
		return fetch(`${this.options.apiUrl}${path}`, {
			method,
			headers,
			body
		});
	}
};
//#endregion
//#region src/vault/db.ts
var DB_NAME = "neoworks-vault-contacts";
var DB_VERSION = 1;
var dbPromise = null;
function open() {
	if (!dbPromise) dbPromise = new Promise((resolve, reject) => {
		const req = indexedDB.open(DB_NAME, DB_VERSION);
		req.onupgradeneeded = () => {
			const db = req.result;
			db.createObjectStore("contacts", { keyPath: "id" }).createIndex("bySpace", "spaceId");
			db.createObjectStore("outbox", { keyPath: "id" }).createIndex("bySpace", "spaceId");
			db.createObjectStore("spaces", { keyPath: "id" });
			db.createObjectStore("meta");
		};
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error);
	});
	return dbPromise;
}
function requestToPromise(request) {
	return new Promise((resolve, reject) => {
		request.onsuccess = () => resolve(request.result);
		request.onerror = () => reject(request.error);
	});
}
async function store(name, mode) {
	return (await open()).transaction(name, mode).objectStore(name);
}
async function putContact(row) {
	await requestToPromise((await store("contacts", "readwrite")).put(row));
}
/** Applies a whole pulled page in one transaction. */
async function putContacts(rows) {
	if (rows.length === 0) return;
	const db = await open();
	return new Promise((resolve, reject) => {
		const tx = db.transaction("contacts", "readwrite");
		const contacts = tx.objectStore("contacts");
		for (const row of rows) contacts.put(row);
		tx.oncomplete = () => resolve();
		tx.onerror = () => reject(tx.error);
	});
}
async function getContact(id) {
	return await requestToPromise((await store("contacts", "readonly")).get(id)) ?? null;
}
async function listContacts() {
	return requestToPromise((await store("contacts", "readonly")).getAll());
}
async function listContactsBySpace(spaceId) {
	return requestToPromise((await store("contacts", "readonly")).index("bySpace").getAll(spaceId));
}
async function putOutbox(entry) {
	await requestToPromise((await store("outbox", "readwrite")).put(entry));
}
async function getOutbox(id) {
	return await requestToPromise((await store("outbox", "readonly")).get(id)) ?? null;
}
async function listOutboxBySpace(spaceId) {
	return requestToPromise((await store("outbox", "readonly")).index("bySpace").getAll(spaceId));
}
async function deleteOutbox(id) {
	await requestToPromise((await store("outbox", "readwrite")).delete(id));
}
async function putSpaceState(state) {
	await requestToPromise((await store("spaces", "readwrite")).put(state));
}
async function getSpaceState(id) {
	return await requestToPromise((await store("spaces", "readonly")).get(id)) ?? null;
}
async function listSpaceStates() {
	return requestToPromise((await store("spaces", "readonly")).getAll());
}
/** Wipes one space's rows + cursor (410 cursor_purged → full resync). */
async function wipeSpace(spaceId) {
	const rows = await listContactsBySpace(spaceId);
	const db = await open();
	await new Promise((resolve, reject) => {
		const tx = db.transaction(["contacts", "spaces"], "readwrite");
		const contacts = tx.objectStore("contacts");
		for (const row of rows) contacts.delete(row.id);
		tx.oncomplete = () => resolve();
		tx.onerror = () => reject(tx.error);
	});
	const state = await getSpaceState(spaceId);
	if (state) await putSpaceState({
		...state,
		cursor: 0
	});
}
/** Guards against a hostile buffer driving unbounded recursion. */
var MAX_DEPTH = 100;
/** Above this a double can no longer represent every integer exactly. */
var MAX_SAFE = 9007199254740991;
var TWO_TO_32 = 4294967296;
var CodecError = class extends Error {
	constructor(code, path, message) {
		super(path.length > 0 ? path + ": " + message : message);
		this.code = code;
		this.path = path;
		this.name = "CodecError";
	}
};
var textEncoder = new TextEncoder();
var textDecoder = new TextDecoder("utf-8", { fatal: true });
function isSurrogatePair(value, index) {
	if ((value.charCodeAt(index) & 64512) !== 55296) return false;
	return (value.charCodeAt(index + 1) & 64512) === 56320;
}
function utf8Length(value) {
	let length = 0;
	for (let index = 0; index < value.length; index++) {
		const code = value.charCodeAt(index);
		if (code < 128) {
			length += 1;
			continue;
		}
		if (code < 2048) {
			length += 2;
			continue;
		}
		if (isSurrogatePair(value, index)) {
			length += 4;
			index++;
			continue;
		}
		length += 3;
	}
	return length;
}
/** The caller has already reserved utf8Length(value) bytes at offset. */
function writeUtf8(bytes, offset, value) {
	let position = offset;
	for (let index = 0; index < value.length; index++) {
		let code = value.charCodeAt(index);
		if (code < 128) {
			bytes[position++] = code;
			continue;
		}
		if (code < 2048) {
			bytes[position++] = 192 | code >> 6;
			bytes[position++] = 128 | code & 63;
			continue;
		}
		if (isSurrogatePair(value, index)) {
			code = 65536 + ((code & 1023) << 10) + (value.charCodeAt(++index) & 1023);
			bytes[position++] = 240 | code >> 18;
			bytes[position++] = 128 | code >> 12 & 63;
			bytes[position++] = 128 | code >> 6 & 63;
			bytes[position++] = 128 | code & 63;
			continue;
		}
		if ((code & 63488) === 55296) code = 65533;
		bytes[position++] = 224 | code >> 12;
		bytes[position++] = 128 | code >> 6 & 63;
		bytes[position++] = 128 | code & 63;
	}
}
/** Bytes a varint of this non-negative value occupies. */
function varintWidth(value) {
	if (value < 128) return 1;
	if (value < 16384) return 2;
	if (value < 2097152) return 3;
	if (value < 268435456) return 4;
	return 5;
}
function writeVarintAt(bytes, offset, value) {
	let position = offset;
	let remaining = value;
	while (remaining > 127) {
		bytes[position++] = remaining & 127 | 128;
		remaining >>>= 7;
	}
	bytes[position] = remaining;
}
/**
* The buffer of the last finished Writer, kept for the next one. Encoding is
* synchronous and single-threaded, so at most one top-level Writer is live at
* a time; a nested Writer (map keys) simply misses the pool while the outer
* one holds it. Steady state: zero buffer allocations and zero grows per row.
*/
var pooledBuffer = null;
/** Rows larger than this are rare enough that retaining the buffer is waste. */
var MAX_POOLED_CAPACITY = 65536;
var Writer = class {
	constructor(capacity = 256) {
		this.view = null;
		this.length = 0;
		if (pooledBuffer !== null && pooledBuffer.length >= capacity) {
			this.bytes = pooledBuffer;
			pooledBuffer = null;
			return;
		}
		this.bytes = new Uint8Array(capacity);
	}
	reserve(extra) {
		const needed = this.length + extra;
		if (needed <= this.bytes.length) return;
		let capacity = this.bytes.length * 2;
		while (capacity < needed) capacity *= 2;
		const grown = new Uint8Array(capacity);
		grown.set(this.bytes.subarray(0, this.length));
		this.bytes = grown;
		this.view = null;
	}
	raw(source) {
		const count = source.length;
		this.reserve(count);
		if (count <= 32) {
			const bytes = this.bytes;
			let position = this.length;
			for (let index = 0; index < count; index++) bytes[position++] = source[index];
		} else this.bytes.set(source, this.length);
		this.length += count;
	}
	key(tag, wire) {
		this.varintNumber(tag * 8 + wire);
	}
	/**
	* The common path. Anything that fits in a double's integer range comes
	* through here; only i64/u64/duration need the BigInt variant below.
	*/
	varintNumber(value) {
		if (value < 0) {
			this.varint(BigInt(value));
			return;
		}
		this.reserve(10);
		const bytes = this.bytes;
		let position = this.length;
		let remaining = value;
		if (remaining <= 2147483647) while (remaining > 127) {
			bytes[position++] = remaining & 127 | 128;
			remaining >>>= 7;
		}
		else while (remaining > 127) {
			bytes[position++] = remaining % 128 | 128;
			remaining = Math.floor(remaining / 128);
		}
		bytes[position++] = remaining;
		this.length = position;
	}
	/** Plain two's-complement varint. Negative values always occupy 10 bytes. */
	varint(value) {
		if (value >= 0n && value <= 9007199254740991n) {
			this.varintNumber(Number(value));
			return;
		}
		this.reserve(10);
		const bytes = this.bytes;
		let position = this.length;
		let remaining = BigInt.asUintN(64, value);
		while (remaining > 127n) {
			bytes[position++] = Number(remaining & 127n) | 128;
			remaining >>= 7n;
		}
		bytes[position++] = Number(remaining);
		this.length = position;
	}
	double(value) {
		this.reserve(8);
		if (this.view === null) this.view = new DataView(this.bytes.buffer);
		this.view.setFloat64(this.length, value, true);
		this.length += 8;
	}
	lengthDelimited(body) {
		this.varintNumber(body.length);
		this.raw(body);
	}
	string(value) {
		if (value.length >= 64) {
			this.longString(value);
			return;
		}
		const byteLength = utf8Length(value);
		this.varintNumber(byteLength);
		this.reserve(byteLength);
		writeUtf8(this.bytes, this.length, value);
		this.length += byteLength;
	}
	longString(value) {
		const lengthOffset = this.beginLengthDelimited();
		this.reserve(value.length * 3);
		const written = textEncoder.encodeInto(value, this.bytes.subarray(this.length)).written;
		this.length += written;
		this.endLengthDelimited(lengthOffset);
	}
	/**
	* Write a nested message body in place, then back-fill its length prefix.
	* The alternative \u2014 a fresh Writer per nesting level, copied back byte by
	* byte \u2014 is what made encoding slower than JSON.stringify.
	*
	* Generated code calls beginNested/endNested directly rather than passing a
	* closure here: a closure per present message field was the single largest
	* cost in the encode profile.
	*/
	nested(write) {
		const lengthOffset = this.beginLengthDelimited();
		write(this);
		this.endLengthDelimited(lengthOffset);
	}
	beginNested() {
		return this.beginLengthDelimited();
	}
	endNested(lengthOffset) {
		this.endLengthDelimited(lengthOffset);
	}
	/** Reserves one byte for the length, which covers bodies under 128 bytes. */
	beginLengthDelimited() {
		this.reserve(1);
		const offset = this.length;
		this.length += 1;
		return offset;
	}
	endLengthDelimited(lengthOffset) {
		const bodyStart = lengthOffset + 1;
		const bodyLength = this.length - bodyStart;
		const width = varintWidth(bodyLength);
		if (width > 1) {
			this.reserve(width - 1);
			this.bytes.copyWithin(bodyStart + width - 1, bodyStart, this.length);
			this.length += width - 1;
		}
		writeVarintAt(this.bytes, lengthOffset, bodyLength);
	}
	finish() {
		const result = this.bytes.slice(0, this.length);
		if (this.bytes.length <= MAX_POOLED_CAPACITY && (pooledBuffer === null || pooledBuffer.length < this.bytes.length)) pooledBuffer = this.bytes;
		return result;
	}
};
/** Shared float conversion area \u2014 cheaper than a DataView per read. */
var scratchBytes = /* @__PURE__ */ new Uint8Array(8);
var scratchView = new DataView(scratchBytes.buffer);
function copyToScratch(buffer, position, count) {
	for (let index = 0; index < count; index++) scratchBytes[index] = buffer[position + index];
}
/**
* null when any byte is non-ASCII; the caller falls back to TextDecoder.
* Rope concatenation measures faster here than fromCharCode.apply and than
* TextDecoder itself for the short fields that dominate real rows.
*/
function asciiString(buffer, start, length) {
	const end = start + length;
	for (let index = start; index < end; index++) if (buffer[index] > 127) return null;
	let out = "";
	for (let index = start; index < end; index++) out += String.fromCharCode(buffer[index]);
	return out;
}
var Reader = class Reader {
	constructor(buffer, position, end, depth, path) {
		this.buffer = buffer;
		this.position = position;
		this.end = end;
		this.depth = depth;
		this.path = path;
		this.lo = 0;
		this.hi = 0;
	}
	static of(bytes, path) {
		return new Reader(bytes, 0, bytes.length, 0, path);
	}
	hasMore() {
		return this.position < this.end;
	}
	require(count) {
		if (this.position + count > this.end) throw new CodecError("TRUNCATED", this.path, "buffer ended mid-value");
	}
	/**
	* Decode one varint into lo/hi without allocating. Bytes 1-4 fill the low 28
	* bits, byte 5 straddles the halves, bytes 6-10 fill the high word.
	*/
	readVarint64() {
		const buffer = this.buffer;
		const end = this.end;
		let position = this.position;
		let lo = 0;
		let hi = 0;
		let byte = 0;
		for (let shift = 0; shift < 28; shift += 7) {
			if (position >= end) throw this.truncated();
			byte = buffer[position++];
			lo |= (byte & 127) << shift;
			if (byte < 128) {
				this.commitVarint(position, lo, 0);
				return;
			}
		}
		if (position >= end) throw this.truncated();
		byte = buffer[position++];
		lo |= (byte & 15) << 28;
		hi = (byte & 127) >> 4;
		if (byte < 128) {
			this.commitVarint(position, lo, hi);
			return;
		}
		for (let shift = 3; shift < 32; shift += 7) {
			if (position >= end) throw this.truncated();
			byte = buffer[position++];
			hi |= (byte & 127) << shift;
			if (byte < 128) {
				this.commitVarint(position, lo, hi);
				return;
			}
		}
		throw new CodecError("OVERLONG_VARINT", this.path, "varint exceeds 10 bytes");
	}
	commitVarint(position, lo, hi) {
		this.position = position;
		this.lo = lo >>> 0;
		this.hi = hi >>> 0;
	}
	truncated() {
		return new CodecError("TRUNCATED", this.path, "buffer ended mid-value");
	}
	/** The raw 64-bit value, unsigned. Only for i64/u64/duration. */
	varint() {
		this.readVarint64();
		if (this.hi === 0) return BigInt(this.lo);
		return BigInt(this.hi) << 32n | BigInt(this.lo);
	}
	varintUnsigned(path) {
		this.readVarint64();
		return unsignedFromHalves(this.lo, this.hi, path);
	}
	varintSigned(path) {
		this.readVarint64();
		return signedFromHalves(this.lo, this.hi, path);
	}
	skipVarint() {
		this.readVarint64();
	}
	key() {
		this.readVarint64();
		if (this.hi !== 0) throw new CodecError("BAD_TAG", this.path, "wire key exceeds 32 bits");
		return this.lo;
	}
	/** A length prefix: non-negative and inside the remaining buffer. */
	length() {
		this.readVarint64();
		const value = unsignedFromHalves(this.lo, this.hi, this.path);
		if (this.position + value > this.end) throw new CodecError("TRUNCATED", this.path, "length-delimited field runs past the buffer");
		return value;
	}
	double() {
		this.require(8);
		copyToScratch(this.buffer, this.position, 8);
		this.position += 8;
		return scratchView.getFloat64(0, true);
	}
	float32() {
		this.require(4);
		copyToScratch(this.buffer, this.position, 4);
		this.position += 4;
		return scratchView.getFloat32(0, true);
	}
	lengthDelimited() {
		const length = this.length();
		const slice = this.buffer.subarray(this.position, this.position + length);
		this.position += length;
		return slice;
	}
	/**
	* A bounded Reader over the next LEN field, one level deeper. Bounds are
	* carried as offsets into the same buffer, so no slice is materialised.
	*/
	subMessage(path) {
		if (this.depth + 1 > MAX_DEPTH) throw new CodecError("DEPTH", path, "message nesting exceeds 100");
		const length = this.length();
		const start = this.position;
		this.position += length;
		return new Reader(this.buffer, start, start + length, this.depth + 1, path);
	}
	/** A bounded Reader over a packed repeated body. */
	packed(path) {
		const length = this.length();
		const start = this.position;
		this.position += length;
		return new Reader(this.buffer, start, start + length, this.depth, path);
	}
	string() {
		const length = this.length();
		const start = this.position;
		this.position += length;
		if (length <= 64) {
			const ascii = asciiString(this.buffer, start, length);
			if (ascii !== null) return ascii;
		}
		try {
			return textDecoder.decode(this.buffer.subarray(start, start + length));
		} catch {
			throw new CodecError("BAD_UTF8", this.path, "field is not valid UTF-8");
		}
	}
	bytes() {
		return this.lengthDelimited().slice();
	}
	/** Consume one field, returning key + body verbatim for unknown-field capture. */
	captureRaw(key, wire) {
		const start = this.position;
		this.skipBody(wire);
		const bodyLength = this.position - start;
		const keyWidth = varintWidth(key);
		const raw = new Uint8Array(keyWidth + bodyLength);
		writeVarintAt(raw, 0, key);
		raw.set(this.buffer.subarray(start, this.position), keyWidth);
		return raw;
	}
	skipBody(wire) {
		if (wire === 0) {
			this.skipVarint();
			return;
		}
		if (wire === 1) {
			this.require(8);
			this.position += 8;
			return;
		}
		if (wire === 5) {
			this.require(4);
			this.position += 4;
			return;
		}
		if (wire === 2) {
			const bodyLength = this.length();
			this.position += bodyLength;
			return;
		}
		throw new CodecError("BAD_WIRE_TYPE", this.path, "unsupported wire type " + wire);
	}
};
function unsignedFromHalves(lo, hi, path) {
	if (hi > 2097151) throw new CodecError("PRECISION", path, "integer exceeds the safe range for a JS number");
	return hi * TWO_TO_32 + lo;
}
function signedFromHalves(lo, hi, path) {
	if ((hi & 2147483648) === 0) return unsignedFromHalves(lo, hi, path);
	let negatedLo = ~lo + 1 >>> 0;
	let negatedHi = ~hi >>> 0;
	if (negatedLo === 0) negatedHi = negatedHi + 1 >>> 0;
	const magnitude = negatedHi * TWO_TO_32 + negatedLo;
	if (magnitude > MAX_SAFE) throw new CodecError("PRECISION", path, "integer exceeds the safe range for a JS number");
	return -magnitude;
}
function requireInteger(value, path) {
	if (!Number.isFinite(value)) throw new CodecError("RANGE", path, "value is not finite");
	if (!Number.isInteger(value)) throw new CodecError("RANGE", path, "value is not an integer");
	return value;
}
function requireFinite(value, path) {
	if (typeof value !== "number") throw new CodecError("TYPE", path, "expected a number");
	return value;
}
var HEX = "0123456789abcdef";
/** 512 two-character strings, so formatting a uuid is 16 lookups and a join. */
var HEX_PAIRS = (() => {
	const pairs = new Array(256);
	for (let i = 0; i < 256; i++) pairs[i] = HEX[i >> 4] + HEX[i & 15];
	return pairs;
})();
/** -1 for any character that is not a hex digit. */
var HEX_VALUES = (() => {
	const values = (/* @__PURE__ */ new Int8Array(128)).fill(-1);
	for (let i = 0; i < 16; i++) {
		values[HEX.charCodeAt(i)] = i;
		values["0123456789ABCDEF".charCodeAt(i)] = i;
	}
	return values;
})();
function uuidToBytes(value, path) {
	const out = /* @__PURE__ */ new Uint8Array(16);
	let written = 0;
	let high = -1;
	for (let index = 0; index < value.length; index++) {
		const code = value.charCodeAt(index);
		if (code === 45) continue;
		const digit = code < 128 ? HEX_VALUES[code] : -1;
		if (digit < 0 || written === 16) throw new CodecError("BAD_UUID", path, "not a uuid: " + value);
		if (high < 0) {
			high = digit;
			continue;
		}
		out[written++] = high << 4 | digit;
		high = -1;
	}
	if (written !== 16 || high >= 0) throw new CodecError("BAD_UUID", path, "not a uuid: " + value);
	return out;
}
function bytesToUuid(bytes, path) {
	if (bytes.length !== 16) throw new CodecError("BAD_UUID", path, "uuid must be 16 bytes, got " + bytes.length);
	return HEX_PAIRS[bytes[0]] + HEX_PAIRS[bytes[1]] + HEX_PAIRS[bytes[2]] + HEX_PAIRS[bytes[3]] + "-" + HEX_PAIRS[bytes[4]] + HEX_PAIRS[bytes[5]] + "-" + HEX_PAIRS[bytes[6]] + HEX_PAIRS[bytes[7]] + "-" + HEX_PAIRS[bytes[8]] + HEX_PAIRS[bytes[9]] + "-" + HEX_PAIRS[bytes[10]] + HEX_PAIRS[bytes[11]] + HEX_PAIRS[bytes[12]] + HEX_PAIRS[bytes[13]] + HEX_PAIRS[bytes[14]] + HEX_PAIRS[bytes[15]];
}
var MS_PER_DAY = 864e5;
var MIN_FOUR_DIGIT_MS = -719528 * MS_PER_DAY;
var MAX_FOUR_DIGIT_MS = 2932897 * MS_PER_DAY - 1;
/** -1 unless both characters are digits. */
function twoDigits(value, index) {
	const high = value.charCodeAt(index) - 48;
	const low = value.charCodeAt(index + 1) - 48;
	if (high < 0 || high > 9 || low < 0 || low > 9) return -1;
	return high * 10 + low;
}
function daysInMonth(year, month) {
	if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
	if (month === 4 || month === 6 || month === 9 || month === 11) return 30;
	return 31;
}
/** Howard Hinnant's days_from_civil; exact for every proleptic Gregorian date. */
function daysFromCivil(year, month, day) {
	const shiftedYear = month <= 2 ? year - 1 : year;
	const era = Math.floor(shiftedYear / 400);
	const yearOfEra = shiftedYear - era * 400;
	const monthIndex = month > 2 ? month - 3 : month + 9;
	const dayOfYear = Math.floor((153 * monthIndex + 2) / 5) + day - 1;
	const dayOfEra = yearOfEra * 365 + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100) + dayOfYear;
	return era * 146097 + dayOfEra - 719468;
}
/** The inverse, packed as year * 10000 + month * 100 + day to avoid an allocation. */
function civilFromDays(days) {
	const shifted = days + 719468;
	const era = Math.floor(shifted / 146097);
	const dayOfEra = shifted - era * 146097;
	const yearOfEra = Math.floor((dayOfEra - Math.floor(dayOfEra / 1460) + Math.floor(dayOfEra / 36524) - Math.floor(dayOfEra / 146096)) / 365);
	const dayOfYear = dayOfEra - (yearOfEra * 365 + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100));
	const monthIndex = Math.floor((5 * dayOfYear + 2) / 153);
	const day = dayOfYear - Math.floor((153 * monthIndex + 2) / 5) + 1;
	const month = monthIndex < 10 ? monthIndex + 3 : monthIndex - 9;
	return (yearOfEra + era * 400 + (month <= 2 ? 1 : 0)) * 1e4 + month * 100 + day;
}
/** Epoch days for a plain YYYY-MM-DD, or NaN when the shape or range is off. */
function parseIsoDate(value) {
	const yearHigh = twoDigits(value, 0);
	const yearLow = twoDigits(value, 2);
	const month = twoDigits(value, 5);
	const day = twoDigits(value, 8);
	if (yearHigh < 0 || yearLow < 0 || month < 0 || day < 0) return NaN;
	if (value.charCodeAt(4) !== 45 || value.charCodeAt(7) !== 45) return NaN;
	const year = yearHigh * 100 + yearLow;
	if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) return NaN;
	return daysFromCivil(year, month, day);
}
/** "00".."99", so zero-padding is a lookup instead of a padStart call. */
var TWO_DIGIT_STRINGS = (() => {
	const strings = new Array(100);
	for (let value = 0; value < 100; value++) strings[value] = String(Math.floor(value / 10)) + String(value % 10);
	return strings;
})();
function formatIsoDate(packed) {
	const year = Math.floor(packed / 1e4);
	const month = Math.floor(packed / 100) % 100;
	const day = packed % 100;
	return TWO_DIGIT_STRINGS[Math.floor(year / 100)] + TWO_DIGIT_STRINGS[year % 100] + "-" + TWO_DIGIT_STRINGS[month] + "-" + TWO_DIGIT_STRINGS[day];
}
var lastFormattedDays = NaN;
var lastFormattedDate = "";
function formatDateFromDays(days) {
	if (days === lastFormattedDays) return lastFormattedDate;
	const formatted = formatIsoDate(civilFromDays(days));
	lastFormattedDays = days;
	lastFormattedDate = formatted;
	return formatted;
}
/** Epoch ms for the exact toISOString shape YYYY-MM-DDTHH:MM:SS.sssZ, else NaN. */
function parseIsoUtcTimestamp(value) {
	if (value.length !== 24) return NaN;
	if (value.charCodeAt(10) !== 84 || value.charCodeAt(13) !== 58 || value.charCodeAt(16) !== 58 || value.charCodeAt(19) !== 46 || value.charCodeAt(23) !== 90) return NaN;
	const days = parseIsoDate(value);
	const hours = twoDigits(value, 11);
	const minutes = twoDigits(value, 14);
	const seconds = twoDigits(value, 17);
	const millisHigh = twoDigits(value, 20);
	const millisLow = value.charCodeAt(22) - 48;
	if (Number.isNaN(days) || hours < 0 || minutes < 0 || seconds < 0 || millisHigh < 0) return NaN;
	if (millisLow < 0 || millisLow > 9) return NaN;
	if (hours > 23 || minutes > 59 || seconds > 59) return NaN;
	const secondOfDay = hours * 3600 + minutes * 60 + seconds;
	return days * MS_PER_DAY + secondOfDay * 1e3 + millisHigh * 10 + millisLow;
}
function timestampToMillis(value, path) {
	const fast = parseIsoUtcTimestamp(value);
	if (!Number.isNaN(fast)) return fast;
	const ms = Date.parse(value);
	if (Number.isNaN(ms)) throw new CodecError("BAD_TIMESTAMP", path, "invalid timestamp " + value);
	return ms;
}
function millisToTimestamp(ms, path) {
	if (Number.isInteger(ms) && ms >= MIN_FOUR_DIGIT_MS && ms <= MAX_FOUR_DIGIT_MS) return formatIsoUtcTimestamp(ms);
	const date = new Date(ms);
	if (Number.isNaN(date.getTime())) throw new CodecError("BAD_TIMESTAMP", path, "timestamp out of range");
	return date.toISOString();
}
function formatIsoUtcTimestamp(ms) {
	const days = Math.floor(ms / MS_PER_DAY);
	const msOfDay = ms - days * MS_PER_DAY;
	const secondOfDay = Math.floor(msOfDay / 1e3);
	const millis = msOfDay - secondOfDay * 1e3;
	const hours = Math.floor(secondOfDay / 3600);
	const minutes = Math.floor(secondOfDay % 3600 / 60);
	const seconds = secondOfDay % 60;
	return formatDateFromDays(days) + "T" + TWO_DIGIT_STRINGS[hours] + ":" + TWO_DIGIT_STRINGS[minutes] + ":" + TWO_DIGIT_STRINGS[seconds] + "." + TWO_DIGIT_STRINGS[Math.floor(millis / 10)] + String(millis % 10) + "Z";
}
/**
* Sort captured unknown fields by tag so they can be interleaved into the known
* fields' ascending order. Array.prototype.sort is stable, so several entries
* sharing a tag keep their original relative order.
*/
function prepareUnknown(unknown, known, path) {
	if (unknown === void 0 || unknown.length === 0) return [];
	for (const field of unknown) if (known.has(field.tag)) throw new CodecError("UNKNOWN_COLLISION", path, "unknown field carries tag " + field.tag + ", which this message declares");
	return [...unknown].sort((a, b) => a.tag - b.tag);
}
/** Emit every pending unknown field whose tag precedes the given tag. */
function flushUnknownBefore(writer, unknown, index, tag) {
	let cursor = index;
	while (cursor < unknown.length && unknown[cursor].tag < tag) {
		writer.raw(unknown[cursor].raw);
		cursor++;
	}
	return cursor;
}
function flushUnknownRest(writer, unknown, index) {
	for (let cursor = index; cursor < unknown.length; cursor++) writer.raw(unknown[cursor].raw);
}
/**
* Capture a field the schema does not declare. Retired tags are dropped instead:
* they are known-dead, so preserving them would grow every row forever.
*/
function captureUnknown(reader, key, tag, wire, into, retired) {
	if (retired.has(tag)) {
		reader.skipBody(wire);
		return into;
	}
	const raw = reader.captureRaw(key, wire);
	const list = into === void 0 ? [] : into;
	list.push({
		tag,
		wire,
		raw
	});
	return list;
}
function missingField(path, name, tag) {
	return new CodecError("MISSING_FIELD", path, "required field '" + name + "' (tag " + tag + ") is absent");
}
function expectWire(actual, expected, path) {
	if (actual === expected) return;
	throw new CodecError("WIRE_MISMATCH", path, "expected wire type " + expected + ", got " + actual);
}
function readSignedField(reader, wire, path) {
	expectWire(wire, 0, path);
	return reader.varintSigned(path);
}
function readUnsignedField(reader, wire, path) {
	expectWire(wire, 0, path);
	return reader.varintUnsigned(path);
}
/**
* f32 and f64 both encode as I64, so this normally reads a double. I32 is
* accepted so payloads written before that rule stay readable.
*/
function readDoubleField(reader, wire, path) {
	if (wire === 5) return reader.float32();
	expectWire(wire, 1, path);
	return reader.double();
}
function readStringField(reader, wire, path) {
	expectWire(wire, 2, path);
	return reader.string();
}
function readBytesField(reader, wire, path) {
	expectWire(wire, 2, path);
	return reader.bytes();
}
var KNOWN_Name = /* @__PURE__ */ new Set([
	1,
	2,
	3,
	4,
	5
]);
var RETIRED_Name = /* @__PURE__ */ new Set([]);
function writeName(w, value, path) {
	const unknown = prepareUnknown(value.$unknown, KNOWN_Name, path);
	let pending = 0;
	pending = flushUnknownBefore(w, unknown, pending, 1);
	if (value.family !== null && value.family !== void 0) {
		const present = value.family;
		w.key(1, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 2);
	if (value.given !== null && value.given !== void 0) {
		const present = value.given;
		w.key(2, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 3);
	if (value.additional !== null && value.additional !== void 0) {
		const present = value.additional;
		w.key(3, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 4);
	if (value.prefixes !== null && value.prefixes !== void 0) {
		const present = value.prefixes;
		w.key(4, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 5);
	if (value.suffixes !== null && value.suffixes !== void 0) {
		const present = value.suffixes;
		w.key(5, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	flushUnknownRest(w, unknown, pending);
}
function readName(r, path) {
	let field1;
	let field2;
	let field3;
	let field4;
	let field5;
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1:
				field1 = readStringField(r, wire, path + ".family");
				break;
			case 2:
				field2 = readStringField(r, wire, path + ".given");
				break;
			case 3: {
				expectWire(wire, 2, path + ".additional");
				const wrapper = r.subMessage(path + ".additional");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField(wrapper, innerWire, path + ".additional"));
				}
				field3 = items;
				break;
			}
			case 4: {
				expectWire(wire, 2, path + ".prefixes");
				const wrapper = r.subMessage(path + ".prefixes");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField(wrapper, innerWire, path + ".prefixes"));
				}
				field4 = items;
				break;
			}
			case 5: {
				expectWire(wire, 2, path + ".suffixes");
				const wrapper = r.subMessage(path + ".suffixes");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField(wrapper, innerWire, path + ".suffixes"));
				}
				field5 = items;
				break;
			}
			default: unknown = captureUnknown(r, wireKey, tag, wire, unknown, RETIRED_Name);
		}
	}
	const result = {
		family: field1,
		given: field2,
		additional: field3,
		prefixes: field4,
		suffixes: field5
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
var KNOWN_Gender = /* @__PURE__ */ new Set([1, 2]);
var RETIRED_Gender = /* @__PURE__ */ new Set([]);
function writeGender(w, value, path) {
	const unknown = prepareUnknown(value.$unknown, KNOWN_Gender, path);
	let pending = 0;
	pending = flushUnknownBefore(w, unknown, pending, 1);
	if (value.sex !== null && value.sex !== void 0) {
		const present = value.sex;
		w.key(1, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 2);
	if (value.identity !== null && value.identity !== void 0) {
		const present = value.identity;
		w.key(2, 2);
		w.string(present);
	}
	flushUnknownRest(w, unknown, pending);
}
function readGender(r, path) {
	let field1;
	let field2;
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1:
				field1 = readStringField(r, wire, path + ".sex");
				break;
			case 2:
				field2 = readStringField(r, wire, path + ".identity");
				break;
			default: unknown = captureUnknown(r, wireKey, tag, wire, unknown, RETIRED_Gender);
		}
	}
	const result = {
		sex: field1,
		identity: field2
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
var KNOWN_Geo = /* @__PURE__ */ new Set([1, 2]);
var RETIRED_Geo = /* @__PURE__ */ new Set([]);
function writeGeo(w, value, path) {
	const unknown = prepareUnknown(value.$unknown, KNOWN_Geo, path);
	let pending = 0;
	pending = flushUnknownBefore(w, unknown, pending, 1);
	w.key(1, 1);
	w.double(requireFinite(value.lat, path + ".lat"));
	pending = flushUnknownBefore(w, unknown, pending, 2);
	w.key(2, 1);
	w.double(requireFinite(value.lng, path + ".lng"));
	flushUnknownRest(w, unknown, pending);
}
function readGeo(r, path) {
	let field1;
	let field2;
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1:
				field1 = readDoubleField(r, wire, path + ".lat");
				break;
			case 2:
				field2 = readDoubleField(r, wire, path + ".lng");
				break;
			default: unknown = captureUnknown(r, wireKey, tag, wire, unknown, RETIRED_Geo);
		}
	}
	if (field1 === void 0) throw missingField(path, "lat", 1);
	if (field2 === void 0) throw missingField(path, "lng", 2);
	const result = {
		lat: field1,
		lng: field2
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
var KNOWN_ContactField = /* @__PURE__ */ new Set([
	1,
	2,
	3,
	4
]);
var RETIRED_ContactField = /* @__PURE__ */ new Set([]);
function writeContactField(w, value, path) {
	const unknown = prepareUnknown(value.$unknown, KNOWN_ContactField, path);
	let pending = 0;
	pending = flushUnknownBefore(w, unknown, pending, 1);
	w.key(1, 2);
	w.string(value.value);
	pending = flushUnknownBefore(w, unknown, pending, 2);
	if (value.types !== null && value.types !== void 0) {
		const present = value.types;
		w.key(2, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 3);
	if (value.pref !== null && value.pref !== void 0) {
		const present = value.pref;
		w.key(3, 0);
		w.varintNumber(requireInteger(present, path + ".pref"));
	}
	pending = flushUnknownBefore(w, unknown, pending, 4);
	if (value.label !== null && value.label !== void 0) {
		const present = value.label;
		w.key(4, 2);
		w.string(present);
	}
	flushUnknownRest(w, unknown, pending);
}
function readContactField(r, path) {
	let field1;
	let field2;
	let field3;
	let field4;
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1:
				field1 = readStringField(r, wire, path + ".value");
				break;
			case 2: {
				expectWire(wire, 2, path + ".types");
				const wrapper = r.subMessage(path + ".types");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField(wrapper, innerWire, path + ".types"));
				}
				field2 = items;
				break;
			}
			case 3:
				field3 = readSignedField(r, wire, path + ".pref");
				break;
			case 4:
				field4 = readStringField(r, wire, path + ".label");
				break;
			default: unknown = captureUnknown(r, wireKey, tag, wire, unknown, RETIRED_ContactField);
		}
	}
	if (field1 === void 0) throw missingField(path, "value", 1);
	const result = {
		value: field1,
		types: field2,
		pref: field3,
		label: field4
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
var KNOWN_Address = /* @__PURE__ */ new Set([
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	9,
	10
]);
var RETIRED_Address = /* @__PURE__ */ new Set([]);
function writeAddress(w, value, path) {
	const unknown = prepareUnknown(value.$unknown, KNOWN_Address, path);
	let pending = 0;
	pending = flushUnknownBefore(w, unknown, pending, 1);
	if (value.types !== null && value.types !== void 0) {
		const present = value.types;
		w.key(1, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 2);
	if (value.pref !== null && value.pref !== void 0) {
		const present = value.pref;
		w.key(2, 0);
		w.varintNumber(requireInteger(present, path + ".pref"));
	}
	pending = flushUnknownBefore(w, unknown, pending, 3);
	if (value.label !== null && value.label !== void 0) {
		const present = value.label;
		w.key(3, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 4);
	if (value.po_box !== null && value.po_box !== void 0) {
		const present = value.po_box;
		w.key(4, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 5);
	if (value.ext !== null && value.ext !== void 0) {
		const present = value.ext;
		w.key(5, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 6);
	if (value.street !== null && value.street !== void 0) {
		const present = value.street;
		w.key(6, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 7);
	if (value.locality !== null && value.locality !== void 0) {
		const present = value.locality;
		w.key(7, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 8);
	if (value.region !== null && value.region !== void 0) {
		const present = value.region;
		w.key(8, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 9);
	if (value.postal_code !== null && value.postal_code !== void 0) {
		const present = value.postal_code;
		w.key(9, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 10);
	if (value.country !== null && value.country !== void 0) {
		const present = value.country;
		w.key(10, 2);
		w.string(present);
	}
	flushUnknownRest(w, unknown, pending);
}
function readAddress(r, path) {
	let field1;
	let field2;
	let field3;
	let field4;
	let field5;
	let field6;
	let field7;
	let field8;
	let field9;
	let field10;
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1: {
				expectWire(wire, 2, path + ".types");
				const wrapper = r.subMessage(path + ".types");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField(wrapper, innerWire, path + ".types"));
				}
				field1 = items;
				break;
			}
			case 2:
				field2 = readSignedField(r, wire, path + ".pref");
				break;
			case 3:
				field3 = readStringField(r, wire, path + ".label");
				break;
			case 4:
				field4 = readStringField(r, wire, path + ".po_box");
				break;
			case 5:
				field5 = readStringField(r, wire, path + ".ext");
				break;
			case 6:
				field6 = readStringField(r, wire, path + ".street");
				break;
			case 7:
				field7 = readStringField(r, wire, path + ".locality");
				break;
			case 8:
				field8 = readStringField(r, wire, path + ".region");
				break;
			case 9:
				field9 = readStringField(r, wire, path + ".postal_code");
				break;
			case 10:
				field10 = readStringField(r, wire, path + ".country");
				break;
			default: unknown = captureUnknown(r, wireKey, tag, wire, unknown, RETIRED_Address);
		}
	}
	const result = {
		types: field1,
		pref: field2,
		label: field3,
		po_box: field4,
		ext: field5,
		street: field6,
		locality: field7,
		region: field8,
		postal_code: field9,
		country: field10
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
var KNOWN_ContactOrganization = /* @__PURE__ */ new Set([1, 2]);
var RETIRED_ContactOrganization = /* @__PURE__ */ new Set([]);
function writeContactOrganization(w, value, path) {
	const unknown = prepareUnknown(value.$unknown, KNOWN_ContactOrganization, path);
	let pending = 0;
	pending = flushUnknownBefore(w, unknown, pending, 1);
	w.key(1, 2);
	w.string(value.name);
	pending = flushUnknownBefore(w, unknown, pending, 2);
	if (value.units !== null && value.units !== void 0) {
		const present = value.units;
		w.key(2, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	flushUnknownRest(w, unknown, pending);
}
function readContactOrganization(r, path) {
	let field1;
	let field2;
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1:
				field1 = readStringField(r, wire, path + ".name");
				break;
			case 2: {
				expectWire(wire, 2, path + ".units");
				const wrapper = r.subMessage(path + ".units");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField(wrapper, innerWire, path + ".units"));
				}
				field2 = items;
				break;
			}
			default: unknown = captureUnknown(r, wireKey, tag, wire, unknown, RETIRED_ContactOrganization);
		}
	}
	if (field1 === void 0) throw missingField(path, "name", 1);
	const result = {
		name: field1,
		units: field2
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
var KNOWN_CustomField = /* @__PURE__ */ new Set([1, 2]);
var RETIRED_CustomField = /* @__PURE__ */ new Set([]);
function writeCustomField(w, value, path) {
	const unknown = prepareUnknown(value.$unknown, KNOWN_CustomField, path);
	let pending = 0;
	pending = flushUnknownBefore(w, unknown, pending, 1);
	w.key(1, 2);
	w.string(value.label);
	pending = flushUnknownBefore(w, unknown, pending, 2);
	w.key(2, 2);
	w.string(value.value);
	flushUnknownRest(w, unknown, pending);
}
function readCustomField(r, path) {
	let field1;
	let field2;
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1:
				field1 = readStringField(r, wire, path + ".label");
				break;
			case 2:
				field2 = readStringField(r, wire, path + ".value");
				break;
			default: unknown = captureUnknown(r, wireKey, tag, wire, unknown, RETIRED_CustomField);
		}
	}
	if (field1 === void 0) throw missingField(path, "label", 1);
	if (field2 === void 0) throw missingField(path, "value", 2);
	const result = {
		label: field1,
		value: field2
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
var KNOWN_ContactRelation = /* @__PURE__ */ new Set([
	1,
	2,
	3
]);
var RETIRED_ContactRelation = /* @__PURE__ */ new Set([]);
function writeContactRelation(w, value, path) {
	const unknown = prepareUnknown(value.$unknown, KNOWN_ContactRelation, path);
	let pending = 0;
	pending = flushUnknownBefore(w, unknown, pending, 1);
	w.key(1, 2);
	w.lengthDelimited(uuidToBytes(value.contact_id, path + ".contact_id"));
	pending = flushUnknownBefore(w, unknown, pending, 2);
	if (value.types !== null && value.types !== void 0) {
		const present = value.types;
		w.key(2, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 3);
	if (value.pref !== null && value.pref !== void 0) {
		const present = value.pref;
		w.key(3, 0);
		w.varintNumber(requireInteger(present, path + ".pref"));
	}
	flushUnknownRest(w, unknown, pending);
}
function readContactRelation(r, path) {
	let field1;
	let field2;
	let field3;
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1:
				field1 = bytesToUuid(readBytesField(r, wire, path + ".contact_id"), path + ".contact_id");
				break;
			case 2: {
				expectWire(wire, 2, path + ".types");
				const wrapper = r.subMessage(path + ".types");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField(wrapper, innerWire, path + ".types"));
				}
				field2 = items;
				break;
			}
			case 3:
				field3 = readSignedField(r, wire, path + ".pref");
				break;
			default: unknown = captureUnknown(r, wireKey, tag, wire, unknown, RETIRED_ContactRelation);
		}
	}
	if (field1 === void 0) throw missingField(path, "contact_id", 1);
	const result = {
		contact_id: field1,
		types: field2,
		pref: field3
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
var KNOWN_Contact = /* @__PURE__ */ new Set([
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	9,
	10,
	11,
	12,
	13,
	14,
	15,
	16,
	17,
	18,
	19,
	20,
	21,
	22,
	23,
	24,
	25,
	26,
	27,
	28,
	29,
	30,
	31,
	32,
	33,
	34,
	35,
	36,
	37,
	38,
	39
]);
var RETIRED_Contact = /* @__PURE__ */ new Set([]);
function encodeContact(value) {
	const writer = new Writer();
	writeContact(writer, value, "Contact");
	return writer.finish();
}
function writeContact(w, value, path) {
	const unknown = prepareUnknown(value.$unknown, KNOWN_Contact, path);
	let pending = 0;
	pending = flushUnknownBefore(w, unknown, pending, 1);
	w.key(1, 2);
	w.lengthDelimited(uuidToBytes(value.id, path + ".id"));
	pending = flushUnknownBefore(w, unknown, pending, 2);
	w.key(2, 2);
	w.string(value.uid);
	pending = flushUnknownBefore(w, unknown, pending, 3);
	w.key(3, 2);
	w.string(value.kind);
	pending = flushUnknownBefore(w, unknown, pending, 4);
	w.key(4, 2);
	w.string(value.formatted_name);
	pending = flushUnknownBefore(w, unknown, pending, 5);
	if (value.name !== null && value.name !== void 0) {
		const present = value.name;
		w.key(5, 2);
		{
			const nestedOffset = w.beginNested();
			writeName(w, present, path + ".name");
			w.endNested(nestedOffset);
		}
	}
	pending = flushUnknownBefore(w, unknown, pending, 6);
	if (value.nicknames !== null && value.nicknames !== void 0) {
		const present = value.nicknames;
		w.key(6, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 7);
	if (value.birthday !== null && value.birthday !== void 0) {
		const present = value.birthday;
		w.key(7, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 8);
	if (value.anniversary !== null && value.anniversary !== void 0) {
		const present = value.anniversary;
		w.key(8, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 9);
	if (value.gender !== null && value.gender !== void 0) {
		const present = value.gender;
		w.key(9, 2);
		{
			const nestedOffset = w.beginNested();
			writeGender(w, present, path + ".gender");
			w.endNested(nestedOffset);
		}
	}
	pending = flushUnknownBefore(w, unknown, pending, 10);
	if (value.emails !== null && value.emails !== void 0) {
		const present = value.emails;
		w.key(10, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			{
				const nestedOffset = w.beginNested();
				writeContactField(w, item, path + ".emails");
				w.endNested(nestedOffset);
			}
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 11);
	if (value.phones !== null && value.phones !== void 0) {
		const present = value.phones;
		w.key(11, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			{
				const nestedOffset = w.beginNested();
				writeContactField(w, item, path + ".phones");
				w.endNested(nestedOffset);
			}
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 12);
	if (value.impps !== null && value.impps !== void 0) {
		const present = value.impps;
		w.key(12, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			{
				const nestedOffset = w.beginNested();
				writeContactField(w, item, path + ".impps");
				w.endNested(nestedOffset);
			}
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 13);
	if (value.languages !== null && value.languages !== void 0) {
		const present = value.languages;
		w.key(13, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			{
				const nestedOffset = w.beginNested();
				writeContactField(w, item, path + ".languages");
				w.endNested(nestedOffset);
			}
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 14);
	if (value.addresses !== null && value.addresses !== void 0) {
		const present = value.addresses;
		w.key(14, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			{
				const nestedOffset = w.beginNested();
				writeAddress(w, item, path + ".addresses");
				w.endNested(nestedOffset);
			}
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 15);
	if (value.organizations !== null && value.organizations !== void 0) {
		const present = value.organizations;
		w.key(15, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			{
				const nestedOffset = w.beginNested();
				writeContactOrganization(w, item, path + ".organizations");
				w.endNested(nestedOffset);
			}
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 16);
	if (value.title !== null && value.title !== void 0) {
		const present = value.title;
		w.key(16, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 17);
	if (value.role !== null && value.role !== void 0) {
		const present = value.role;
		w.key(17, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 18);
	if (value.timezone !== null && value.timezone !== void 0) {
		const present = value.timezone;
		w.key(18, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 19);
	if (value.geo !== null && value.geo !== void 0) {
		const present = value.geo;
		w.key(19, 2);
		{
			const nestedOffset = w.beginNested();
			writeGeo(w, present, path + ".geo");
			w.endNested(nestedOffset);
		}
	}
	pending = flushUnknownBefore(w, unknown, pending, 20);
	if (value.categories !== null && value.categories !== void 0) {
		const present = value.categories;
		w.key(20, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 21);
	if (value.notes !== null && value.notes !== void 0) {
		const present = value.notes;
		w.key(21, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 22);
	if (value.urls !== null && value.urls !== void 0) {
		const present = value.urls;
		w.key(22, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			{
				const nestedOffset = w.beginNested();
				writeContactField(w, item, path + ".urls");
				w.endNested(nestedOffset);
			}
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 23);
	if (value.source !== null && value.source !== void 0) {
		const present = value.source;
		w.key(23, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 24);
	if (value.prodid !== null && value.prodid !== void 0) {
		const present = value.prodid;
		w.key(24, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 25);
	if (value.fburl !== null && value.fburl !== void 0) {
		const present = value.fburl;
		w.key(25, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 26);
	if (value.caluri !== null && value.caluri !== void 0) {
		const present = value.caluri;
		w.key(26, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 27);
	if (value.caladruri !== null && value.caladruri !== void 0) {
		const present = value.caladruri;
		w.key(27, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 28);
	if (value.photo !== null && value.photo !== void 0) {
		const present = value.photo;
		w.key(28, 2);
		w.lengthDelimited(uuidToBytes(present, path + ".photo"));
	}
	pending = flushUnknownBefore(w, unknown, pending, 29);
	if (value.logo !== null && value.logo !== void 0) {
		const present = value.logo;
		w.key(29, 2);
		w.lengthDelimited(uuidToBytes(present, path + ".logo"));
	}
	pending = flushUnknownBefore(w, unknown, pending, 30);
	if (value.sound !== null && value.sound !== void 0) {
		const present = value.sound;
		w.key(30, 2);
		w.lengthDelimited(uuidToBytes(present, path + ".sound"));
	}
	pending = flushUnknownBefore(w, unknown, pending, 31);
	if (value.key !== null && value.key !== void 0) {
		const present = value.key;
		w.key(31, 2);
		w.lengthDelimited(uuidToBytes(present, path + ".key"));
	}
	pending = flushUnknownBefore(w, unknown, pending, 32);
	if (value.custom_fields !== null && value.custom_fields !== void 0) {
		const present = value.custom_fields;
		w.key(32, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			{
				const nestedOffset = w.beginNested();
				writeCustomField(w, item, path + ".custom_fields");
				w.endNested(nestedOffset);
			}
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 33);
	w.key(33, 0);
	w.varintNumber(value.favorite ? 1 : 0);
	pending = flushUnknownBefore(w, unknown, pending, 34);
	w.key(34, 0);
	w.varintNumber(value.archived ? 1 : 0);
	pending = flushUnknownBefore(w, unknown, pending, 35);
	w.key(35, 0);
	w.varintNumber(value.deleted ? 1 : 0);
	pending = flushUnknownBefore(w, unknown, pending, 36);
	if (value.related !== null && value.related !== void 0) {
		const present = value.related;
		w.key(36, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			{
				const nestedOffset = w.beginNested();
				writeContactRelation(w, item, path + ".related");
				w.endNested(nestedOffset);
			}
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 37);
	if (value.member_ids !== null && value.member_ids !== void 0) {
		const present = value.member_ids;
		w.key(37, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.lengthDelimited(uuidToBytes(item, path + ".member_ids"));
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 38);
	w.key(38, 0);
	w.varintNumber(timestampToMillis(value.created_at, path + ".created_at"));
	pending = flushUnknownBefore(w, unknown, pending, 39);
	w.key(39, 0);
	w.varintNumber(timestampToMillis(value.updated_at, path + ".updated_at"));
	flushUnknownRest(w, unknown, pending);
}
function decodeContact(bytes) {
	return readContact(Reader.of(bytes, "Contact"), "Contact");
}
function readContact(r, path) {
	let field1;
	let field2;
	let field3;
	let field4;
	let field5;
	let field6;
	let field7;
	let field8;
	let field9;
	let field10;
	let field11;
	let field12;
	let field13;
	let field14;
	let field15;
	let field16;
	let field17;
	let field18;
	let field19;
	let field20;
	let field21;
	let field22;
	let field23;
	let field24;
	let field25;
	let field26;
	let field27;
	let field28;
	let field29;
	let field30;
	let field31;
	let field32;
	let field33;
	let field34;
	let field35;
	let field36;
	let field37;
	let field38;
	let field39;
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1:
				field1 = bytesToUuid(readBytesField(r, wire, path + ".id"), path + ".id");
				break;
			case 2:
				field2 = readStringField(r, wire, path + ".uid");
				break;
			case 3:
				field3 = readStringField(r, wire, path + ".kind");
				break;
			case 4:
				field4 = readStringField(r, wire, path + ".formatted_name");
				break;
			case 5:
				field5 = readName((expectWire(wire, 2, path + ".name"), r.subMessage(path + ".name")), path + ".name");
				break;
			case 6: {
				expectWire(wire, 2, path + ".nicknames");
				const wrapper = r.subMessage(path + ".nicknames");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField(wrapper, innerWire, path + ".nicknames"));
				}
				field6 = items;
				break;
			}
			case 7:
				field7 = readStringField(r, wire, path + ".birthday");
				break;
			case 8:
				field8 = readStringField(r, wire, path + ".anniversary");
				break;
			case 9:
				field9 = readGender((expectWire(wire, 2, path + ".gender"), r.subMessage(path + ".gender")), path + ".gender");
				break;
			case 10: {
				expectWire(wire, 2, path + ".emails");
				const wrapper = r.subMessage(path + ".emails");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire(innerWire, 2, path + ".emails"), wrapper.subMessage(path + ".emails")), path + ".emails"));
				}
				field10 = items;
				break;
			}
			case 11: {
				expectWire(wire, 2, path + ".phones");
				const wrapper = r.subMessage(path + ".phones");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire(innerWire, 2, path + ".phones"), wrapper.subMessage(path + ".phones")), path + ".phones"));
				}
				field11 = items;
				break;
			}
			case 12: {
				expectWire(wire, 2, path + ".impps");
				const wrapper = r.subMessage(path + ".impps");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire(innerWire, 2, path + ".impps"), wrapper.subMessage(path + ".impps")), path + ".impps"));
				}
				field12 = items;
				break;
			}
			case 13: {
				expectWire(wire, 2, path + ".languages");
				const wrapper = r.subMessage(path + ".languages");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire(innerWire, 2, path + ".languages"), wrapper.subMessage(path + ".languages")), path + ".languages"));
				}
				field13 = items;
				break;
			}
			case 14: {
				expectWire(wire, 2, path + ".addresses");
				const wrapper = r.subMessage(path + ".addresses");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readAddress((expectWire(innerWire, 2, path + ".addresses"), wrapper.subMessage(path + ".addresses")), path + ".addresses"));
				}
				field14 = items;
				break;
			}
			case 15: {
				expectWire(wire, 2, path + ".organizations");
				const wrapper = r.subMessage(path + ".organizations");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactOrganization((expectWire(innerWire, 2, path + ".organizations"), wrapper.subMessage(path + ".organizations")), path + ".organizations"));
				}
				field15 = items;
				break;
			}
			case 16:
				field16 = readStringField(r, wire, path + ".title");
				break;
			case 17:
				field17 = readStringField(r, wire, path + ".role");
				break;
			case 18:
				field18 = readStringField(r, wire, path + ".timezone");
				break;
			case 19:
				field19 = readGeo((expectWire(wire, 2, path + ".geo"), r.subMessage(path + ".geo")), path + ".geo");
				break;
			case 20: {
				expectWire(wire, 2, path + ".categories");
				const wrapper = r.subMessage(path + ".categories");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField(wrapper, innerWire, path + ".categories"));
				}
				field20 = items;
				break;
			}
			case 21: {
				expectWire(wire, 2, path + ".notes");
				const wrapper = r.subMessage(path + ".notes");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField(wrapper, innerWire, path + ".notes"));
				}
				field21 = items;
				break;
			}
			case 22: {
				expectWire(wire, 2, path + ".urls");
				const wrapper = r.subMessage(path + ".urls");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire(innerWire, 2, path + ".urls"), wrapper.subMessage(path + ".urls")), path + ".urls"));
				}
				field22 = items;
				break;
			}
			case 23:
				field23 = readStringField(r, wire, path + ".source");
				break;
			case 24:
				field24 = readStringField(r, wire, path + ".prodid");
				break;
			case 25:
				field25 = readStringField(r, wire, path + ".fburl");
				break;
			case 26:
				field26 = readStringField(r, wire, path + ".caluri");
				break;
			case 27:
				field27 = readStringField(r, wire, path + ".caladruri");
				break;
			case 28:
				field28 = bytesToUuid(readBytesField(r, wire, path + ".photo"), path + ".photo");
				break;
			case 29:
				field29 = bytesToUuid(readBytesField(r, wire, path + ".logo"), path + ".logo");
				break;
			case 30:
				field30 = bytesToUuid(readBytesField(r, wire, path + ".sound"), path + ".sound");
				break;
			case 31:
				field31 = bytesToUuid(readBytesField(r, wire, path + ".key"), path + ".key");
				break;
			case 32: {
				expectWire(wire, 2, path + ".custom_fields");
				const wrapper = r.subMessage(path + ".custom_fields");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readCustomField((expectWire(innerWire, 2, path + ".custom_fields"), wrapper.subMessage(path + ".custom_fields")), path + ".custom_fields"));
				}
				field32 = items;
				break;
			}
			case 33:
				field33 = readUnsignedField(r, wire, path + ".favorite") !== 0;
				break;
			case 34:
				field34 = readUnsignedField(r, wire, path + ".archived") !== 0;
				break;
			case 35:
				field35 = readUnsignedField(r, wire, path + ".deleted") !== 0;
				break;
			case 36: {
				expectWire(wire, 2, path + ".related");
				const wrapper = r.subMessage(path + ".related");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactRelation((expectWire(innerWire, 2, path + ".related"), wrapper.subMessage(path + ".related")), path + ".related"));
				}
				field36 = items;
				break;
			}
			case 37: {
				expectWire(wire, 2, path + ".member_ids");
				const wrapper = r.subMessage(path + ".member_ids");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(bytesToUuid(readBytesField(wrapper, innerWire, path + ".member_ids"), path + ".member_ids"));
				}
				field37 = items;
				break;
			}
			case 38:
				field38 = millisToTimestamp(readSignedField(r, wire, path + ".created_at"), path + ".created_at");
				break;
			case 39:
				field39 = millisToTimestamp(readSignedField(r, wire, path + ".updated_at"), path + ".updated_at");
				break;
			default: unknown = captureUnknown(r, wireKey, tag, wire, unknown, RETIRED_Contact);
		}
	}
	if (field1 === void 0) throw missingField(path, "id", 1);
	if (field2 === void 0) throw missingField(path, "uid", 2);
	if (field3 === void 0) throw missingField(path, "kind", 3);
	if (field4 === void 0) throw missingField(path, "formatted_name", 4);
	if (field33 === void 0) throw missingField(path, "favorite", 33);
	if (field34 === void 0) throw missingField(path, "archived", 34);
	if (field35 === void 0) throw missingField(path, "deleted", 35);
	if (field38 === void 0) throw missingField(path, "created_at", 38);
	if (field39 === void 0) throw missingField(path, "updated_at", 39);
	const result = {
		id: field1,
		uid: field2,
		kind: field3,
		formatted_name: field4,
		name: field5,
		nicknames: field6,
		birthday: field7,
		anniversary: field8,
		gender: field9,
		emails: field10,
		phones: field11,
		impps: field12,
		languages: field13,
		addresses: field14,
		organizations: field15,
		title: field16,
		role: field17,
		timezone: field18,
		geo: field19,
		categories: field20,
		notes: field21,
		urls: field22,
		source: field23,
		prodid: field24,
		fburl: field25,
		caluri: field26,
		caladruri: field27,
		photo: field28,
		logo: field29,
		sound: field30,
		key: field31,
		custom_fields: field32,
		favorite: field33,
		archived: field34,
		deleted: field35,
		related: field36,
		member_ids: field37,
		created_at: field38,
		updated_at: field39
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
//#endregion
//#region src/vault/envelope.ts
function encodeRow(contact) {
	return encodeContact(contact);
}
function decodeRow(bytes) {
	return decodeContact(bytes);
}
function bytesToBase64(bytes) {
	let binary = "";
	for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
	return btoa(binary);
}
function base64ToBytes(value) {
	const binary = atob(value);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}
/** Builds the local row for a decrypted + decoded pulled envelope. */
function wireToLocal(envelope, data) {
	return {
		id: envelope.item_id,
		spaceId: envelope.space_id,
		seq: envelope.seq,
		keyEpoch: envelope.key_epoch,
		schemaVer: envelope.schema_ver,
		deleted: envelope.deleted,
		authorId: envelope.author_id,
		createdAt: envelope.created_at,
		updatedAt: envelope.updated_at,
		data
	};
}
//#endregion
//#region src/vault/merge.ts
function mergeContacts(local, remote) {
	if (local.updatedAt > remote.updatedAt) return local.data;
	if (local.updatedAt < remote.updatedAt) return remote.data;
	if (local.authorId > remote.authorId) return local.data;
	if (local.authorId < remote.authorId) return remote.data;
	if (local.seq > remote.seq) return local.data;
	return remote.data;
}
//#endregion
//#region src/vault/query.ts
function lower(value) {
	if (value === null || value === void 0) return "";
	return value.toLowerCase();
}
function matchString(value, filter) {
	if (filter.isNull !== void 0) {
		const isNull = value === void 0 || value === "";
		if (filter.isNull !== isNull) return false;
	}
	const text = lower(value);
	if (filter.eq !== void 0 && filter.eq !== null && value !== filter.eq) return false;
	if (filter.ne !== void 0 && filter.ne !== null && value === filter.ne) return false;
	if (filter.contains && !text.includes(filter.contains.toLowerCase())) return false;
	if (filter.startsWith && !text.startsWith(filter.startsWith.toLowerCase())) return false;
	if (filter.endsWith && !text.endsWith(filter.endsWith.toLowerCase())) return false;
	if (filter.in && !filter.in.includes(value ?? "")) return false;
	if (filter.matches && !matchesRegex(value ?? "", filter.matches)) return false;
	if (filter.search && !text.includes(filter.search.toLowerCase())) return false;
	if (filter.fuzzy && !text.includes(filter.fuzzy.toLowerCase())) return false;
	return true;
}
function matchesRegex(value, pattern) {
	try {
		return new RegExp(pattern).test(value);
	} catch {
		return false;
	}
}
function matchBool(value, filter) {
	if (filter.eq === void 0 || filter.eq === null) return true;
	return value === filter.eq;
}
function matchInt(value, filter) {
	if (filter.eq !== void 0 && filter.eq !== null && value !== filter.eq) return false;
	if (filter.gt !== void 0 && filter.gt !== null && !(value > filter.gt)) return false;
	if (filter.lt !== void 0 && filter.lt !== null && !(value < filter.lt)) return false;
	return true;
}
var DURATION_UNIT_MS = {
	w: 6048e5,
	d: 864e5,
	h: 36e5,
	m: 6e4,
	s: 1e3
};
function durationToMs(spec) {
	let total = 0;
	let matched = false;
	for (const part of spec.matchAll(/(\d+)([wdhms])/g)) {
		total += Number(part[1]) * (DURATION_UNIT_MS[part[2]] ?? 0);
		matched = true;
	}
	if (!matched) return null;
	return total;
}
function matchDate(value, filter) {
	const time = value === void 0 ? NaN : new Date(value).getTime();
	if (filter.eq && time !== new Date(filter.eq).getTime()) return false;
	if (filter.before && !(time < new Date(filter.before).getTime())) return false;
	if (filter.after && !(time > new Date(filter.after).getTime())) return false;
	if (!filter.withinLast) return true;
	const window = durationToMs(filter.withinLast);
	if (window === null) return false;
	return time >= Date.now() - window;
}
function matchStringList(values, filter) {
	if (filter.hasAll && !filter.hasAll.every((needle) => values.includes(needle))) return false;
	if (filter.hasAny && !filter.hasAny.some((needle) => values.includes(needle))) return false;
	if (filter.contains) {
		const needle = filter.contains.toLowerCase();
		if (!values.some((entry) => entry.toLowerCase().includes(needle))) return false;
	}
	if (filter.isEmpty !== void 0 && filter.isEmpty !== null && filter.isEmpty !== (values.length === 0)) return false;
	if (filter.size && !matchInt(values.length, filter.size)) return false;
	return true;
}
function matchFieldList(fields, filter) {
	if (filter.any) {
		const condition = filter.any;
		if (!fields.some((field) => {
			if (condition.value && !matchString(field.value, condition.value)) return false;
			if (condition.type && !(field.types ?? []).includes(condition.type)) return false;
			return true;
		})) return false;
	}
	if (filter.isEmpty !== void 0 && filter.isEmpty !== null && filter.isEmpty !== (fields.length === 0)) return false;
	if (filter.size && !matchInt(fields.length, filter.size)) return false;
	return true;
}
var EARTH_RADIUS_METERS = 6371e3;
function haversineMeters(a, b) {
	const toRad = (deg) => deg * Math.PI / 180;
	const dLat = toRad(b.lat - a.lat);
	const dLng = toRad(b.lng - a.lng);
	const h = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLng / 2) ** 2;
	return 2 * EARTH_RADIUS_METERS * Math.asin(Math.sqrt(h));
}
function matchGeo(point, filter) {
	if (filter.isNull !== void 0 && filter.isNull !== (point === void 0)) return false;
	if (filter.within) return false;
	if (!filter.near) return true;
	if (point === void 0) return false;
	return haversineMeters(point, filter.near) <= filter.near.radiusMeters;
}
function list(value) {
	if (!value) return [];
	return [...value];
}
/** Evaluates a ContactFilter tree against one decrypted contact. */
function matchesFilter(contact, filter) {
	if (filter.and && !filter.and.every((sub) => matchesFilter(contact, sub))) return false;
	if (filter.or && !filter.or.some((sub) => matchesFilter(contact, sub))) return false;
	if (filter.not && matchesFilter(contact, filter.not)) return false;
	if (filter.formatted_name && !matchString(contact.formatted_name, filter.formatted_name)) return false;
	if (filter.kind && !matchString(contact.kind, filter.kind)) return false;
	if (filter.birthday && !matchString(contact.birthday, filter.birthday)) return false;
	if (filter.anniversary && !matchString(contact.anniversary, filter.anniversary)) return false;
	if (filter.title && !matchString(contact.title, filter.title)) return false;
	if (filter.role && !matchString(contact.role, filter.role)) return false;
	if (filter.timezone && !matchString(contact.timezone, filter.timezone)) return false;
	if (filter.favorite && !matchBool(contact.favorite, filter.favorite)) return false;
	if (filter.archived && !matchBool(contact.archived, filter.archived)) return false;
	if (filter.deleted && !matchBool(contact.deleted, filter.deleted)) return false;
	if (filter.categories && !matchStringList(list(contact.categories), filter.categories)) return false;
	if (filter.nicknames && !matchStringList(list(contact.nicknames), filter.nicknames)) return false;
	if (filter.notes && !matchStringList(list(contact.notes), filter.notes)) return false;
	if (filter.emails && !matchFieldList(list(contact.emails), filter.emails)) return false;
	if (filter.phones && !matchFieldList(list(contact.phones), filter.phones)) return false;
	if (filter.impps && !matchFieldList(list(contact.impps), filter.impps)) return false;
	if (filter.languages && !matchFieldList(list(contact.languages), filter.languages)) return false;
	if (filter.urls && !matchFieldList(list(contact.urls), filter.urls)) return false;
	if (filter.created_at && !matchDate(contact.created_at, filter.created_at)) return false;
	if (filter.updated_at && !matchDate(contact.updated_at, filter.updated_at)) return false;
	if (filter.geo && !matchGeo(contact.geo, filter.geo)) return false;
	return true;
}
/** Case-insensitive needle over name, emails and phones (the old server search). */
function matchesSearch(contact, needle) {
	const text = needle.toLowerCase();
	if (lower(contact.formatted_name).includes(text)) return true;
	if (list(contact.emails).some((field) => lower(field.value).includes(text))) return true;
	if (list(contact.phones).some((field) => lower(field.value).includes(text))) return true;
	return false;
}
/** Scope buckets mirror the server's: archived and trashed are separate views. */
function matchesScope(contact, scope) {
	if (scope === "ALL") return true;
	if (scope === "TRASHED") return contact.deleted;
	if (contact.deleted) return false;
	if (scope === "ARCHIVED") return contact.archived;
	return !contact.archived;
}
function compareOn(field, a, b) {
	if (field === "CREATED_AT") return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
	if (field === "UPDATED_AT") return new Date(a.updated_at).getTime() - new Date(b.updated_at).getTime();
	if (field === "BIRTHDAY") return (a.birthday ?? "").localeCompare(b.birthday ?? "");
	return a.formatted_name.localeCompare(b.formatted_name, void 0, { sensitivity: "base" });
}
var DEFAULT_SORT = [{
	field: "FORMATTED_NAME",
	direction: "ASC"
}];
/** Applies ContactSort keys in order; default = formatted_name ascending. */
function sortContacts(rows, sort, pick) {
	const keys = sort && sort.length > 0 ? sort : DEFAULT_SORT;
	const sorted = [...rows];
	sorted.sort((left, right) => {
		for (const key of keys) {
			const direction = key.direction === "DESC" ? -1 : 1;
			const comparison = compareOn(key.field, pick(left), pick(right));
			if (comparison !== 0) return comparison * direction;
		}
		return 0;
	});
	return sorted;
}
/** True when the row passes scope, favorite, search and the filter tree. */
function matchesQuery(contact, options) {
	if (!matchesScope(contact, options.scope)) return false;
	if (options.favorite !== void 0 && contact.favorite !== options.favorite) return false;
	const needle = (options.search ?? "").trim();
	if (needle.length > 0 && !matchesSearch(contact, needle)) return false;
	if (options.filter && !matchesFilter(contact, options.filter)) return false;
	return true;
}
//#endregion
//#region src/vault/engine.ts
var COLLECTION$1 = "contacts";
var PULL_PAGE = 500;
var MAX_PUSH_RETRIES = 5;
/** vCard UID for a new contact; 32 hex chars, minted here so apps never do. */
function mintUid() {
	return crypto.randomUUID().replace(/-/g, "");
}
/**
* Local-first store + sync loop. Reads always come from IndexedDB; writes land
* locally (optimistic) plus in the outbox, then push in the background.
*/
var ContactsEngine = class {
	constructor(deps) {
		this.deps = deps;
		this.listeners = /* @__PURE__ */ new Map();
		this.pollTimer = null;
		this.drainChain = Promise.resolve();
		this.personalSpaceId = null;
		this.started = false;
	}
	on(event, listener) {
		let set = this.listeners.get(event);
		if (!set) {
			set = /* @__PURE__ */ new Set();
			this.listeners.set(event, set);
		}
		set.add(listener);
		return () => set.delete(listener);
	}
	emit(event, detail) {
		this.listeners.get(event)?.forEach((listener) => listener(detail));
	}
	/** Unlocks all spaces, then pulls each and starts the poll + push loops. */
	async start(pollIntervalMs = 3e4) {
		const unlocked = await this.deps.spaces.unlockAll();
		const failed = unlocked.filter((result) => !result.ok);
		if (failed.length > 0) this.emit("error", {
			kind: "unlock",
			failed
		});
		const memberships = await this.deps.spaces.list();
		let personal = memberships.find((membership) => membership.space.kind === "personal");
		if (!personal) personal = await this.deps.spaces.ensurePersonal();
		this.personalSpaceId = personal.space.space_id;
		const okSpaces = new Set(unlocked.filter((result) => result.ok).map((result) => result.spaceId));
		okSpaces.add(personal.space.space_id);
		for (const membership of memberships) {
			if (!okSpaces.has(membership.space.space_id)) continue;
			const existing = await getSpaceState(membership.space.space_id);
			await putSpaceState({
				id: membership.space.space_id,
				kind: membership.space.kind,
				role: membership.member.role,
				keyEpoch: membership.space.key_epoch,
				cursor: existing?.cursor ?? 0,
				latestSeq: membership.space.seq
			});
		}
		this.started = true;
		await this.syncOnce();
		if (pollIntervalMs > 0) this.pollTimer = setInterval(() => {
			this.syncOnce();
		}, pollIntervalMs);
	}
	get isStarted() {
		return this.started;
	}
	stop() {
		if (this.pollTimer) clearInterval(this.pollTimer);
		this.pollTimer = null;
	}
	/** One full cycle: drain the outbox, then pull every space. */
	async syncOnce() {
		try {
			await this.drainOutbox();
			for (const state of await listSpaceStates()) await this.pullSpace(state.id);
		} catch (error) {
			this.emit("error", {
				kind: "sync",
				error
			});
		}
	}
	/** Scope + search + filter + sort + paging, all evaluated on decrypted rows. */
	async list(options = {}) {
		const matched = await this.matchingRows(options);
		const sorted = sortContacts(matched, options.sort, (row) => row.data);
		const offset = options.offset ?? 0;
		const end = options.limit === void 0 ? void 0 : offset + options.limit;
		return {
			items: sorted.slice(offset, end),
			total: matched.length
		};
	}
	/** Number of rows matching the query, ignoring limit/offset. */
	async count(options = {}) {
		return (await this.matchingRows(options)).length;
	}
	/**
	* Rows passing the query. Envelope tombstones (`row.deleted`) are gone for
	* good and never surface in any scope — the restorable trash is the codec
	* payload's own `deleted` flag, which the scope filter handles.
	*/
	async matchingRows(options) {
		return (await listContacts()).filter((row) => !row.deleted && matchesQuery(row.data, options));
	}
	async get(id) {
		return getContact(id);
	}
	/**
	* Decrypted version history of one contact, oldest first. Server-side rows are
	* ciphertext copies made on every update; they decrypt with the same per-epoch
	* space keys.
	*/
	async history(id) {
		const local = await getContact(id);
		if (!local) return [];
		const readable = (await this.deps.sync.versions(local.spaceId, id)).filter((envelope) => !envelope.deleted && envelope.blob);
		const rows = await this.toDecryptRows(readable);
		const decrypted = await this.deps.crypto.spaceDecryptBatch(COLLECTION$1, local.spaceId, rows.map((row) => ({
			header: row.header,
			blob: row.blob
		})));
		const out = [];
		for (let i = 0; i < rows.length; i++) {
			const result = decrypted[i];
			if (result.error !== void 0) continue;
			const envelope = rows[i].envelope;
			out.push({
				seq: envelope.seq,
				createdAt: envelope.created_at,
				authorId: envelope.author_id,
				data: decodeRow(result.plaintext)
			});
		}
		return out;
	}
	/**
	* Creates or updates a contact. Returns the row id. The caller may pass a
	* partial contact: an absent `id` mints a new row, and uid, timestamps and
	* the flag fields are defaulted here rather than by every app.
	*/
	async write(contact, spaceId) {
		const existing = contact.id ? await getContact(contact.id) : null;
		const id = existing?.id ?? (contact.id || crypto.randomUUID());
		const targetSpace = existing?.spaceId ?? spaceId ?? this.personalSpaceId;
		if (!targetSpace) throw new Error("no space available — call start() first");
		const now = (/* @__PURE__ */ new Date()).toISOString();
		const data = {
			kind: "individual",
			formatted_name: "",
			favorite: false,
			archived: false,
			deleted: false,
			...contact,
			id,
			uid: contact.uid || existing?.data.uid || mintUid(),
			created_at: contact.created_at || existing?.createdAt || now,
			updated_at: now
		};
		const state = await getSpaceState(targetSpace);
		await putContact({
			id,
			spaceId: targetSpace,
			seq: existing?.seq ?? 0,
			keyEpoch: state?.keyEpoch ?? 1,
			schemaVer: 1,
			deleted: false,
			authorId: this.deps.ownUserId,
			createdAt: data.created_at,
			updatedAt: now,
			data
		});
		await putOutbox({
			id,
			spaceId: targetSpace,
			baseSeq: existing?.seq ?? 0,
			deleted: false,
			data,
			updatedAt: now,
			attempts: 0
		});
		this.emit("changed");
		this.drainOutbox();
		return id;
	}
	/** Tombstones a contact (server drops the ciphertext). */
	async trash(id) {
		const existing = await getContact(id);
		if (!existing) return;
		const now = (/* @__PURE__ */ new Date()).toISOString();
		await putContact({
			...existing,
			deleted: true,
			updatedAt: now
		});
		await putOutbox({
			id,
			spaceId: existing.spaceId,
			baseSeq: existing.seq,
			deleted: true,
			data: existing.data,
			updatedAt: now,
			attempts: 0
		});
		this.emit("changed");
		this.drainOutbox();
	}
	async pullSpace(spaceId) {
		let state = await getSpaceState(spaceId);
		if (!state) return;
		let cursor = state.cursor;
		for (;;) {
			let page;
			try {
				page = await this.deps.sync.pull(spaceId, cursor, PULL_PAGE);
			} catch (error) {
				if (error.name === "CursorPurgedError") {
					await wipeSpace(spaceId);
					cursor = 0;
					continue;
				}
				throw error;
			}
			if (page.key_epoch !== state.keyEpoch) state = {
				...state,
				keyEpoch: page.key_epoch
			};
			if (page.items.length > 0) {
				await this.applyEnvelopes(spaceId, page.items);
				cursor = page.next_since;
			}
			await putSpaceState({
				...state,
				cursor,
				latestSeq: page.space_seq
			});
			this.emit("progress", {
				spaceId,
				cursor,
				latestSeq: page.space_seq
			});
			if (!page.has_more) break;
		}
		this.emit("changed");
	}
	/** Attaches the author's signer key to each envelope, ready for decryption. */
	async toDecryptRows(envelopes) {
		return Promise.all(envelopes.map(async (envelope) => ({
			envelope,
			header: {
				itemId: envelope.item_id,
				keyEpoch: envelope.key_epoch,
				schemaVer: envelope.schema_ver,
				baseSeq: envelope.base_seq,
				deleted: envelope.deleted,
				sig: envelope.sig ?? "",
				signerPub: await this.deps.spaces.signerPubFor(envelope.author_id),
				authorUserId: envelope.author_id
			},
			blob: envelope.blob ? base64ToBytes(envelope.blob) : /* @__PURE__ */ new Uint8Array(0)
		})));
	}
	async applyEnvelopes(spaceId, envelopes) {
		const rows = await this.toDecryptRows(envelopes);
		const decrypted = await this.deps.crypto.spaceDecryptBatch(COLLECTION$1, spaceId, rows.map((row) => ({
			header: row.header,
			blob: row.blob
		})));
		const toStore = [];
		for (let i = 0; i < rows.length; i++) {
			const { envelope } = rows[i];
			const result = decrypted[i];
			if (result.error !== void 0) {
				this.emit("error", {
					kind: "decrypt",
					itemId: envelope.item_id,
					error: result.error
				});
				continue;
			}
			if (await getOutbox(envelope.item_id)) continue;
			const local = await getContact(envelope.item_id);
			if (local && local.seq >= envelope.seq) continue;
			if (envelope.deleted) {
				if (local) toStore.push({
					...local,
					seq: envelope.seq,
					deleted: true,
					updatedAt: envelope.updated_at
				});
				continue;
			}
			toStore.push(wireToLocal(envelope, decodeRow(result.plaintext)));
		}
		await putContacts(toStore);
	}
	drainOutbox() {
		const pass = this.drainChain.then(() => this.drainPass());
		this.drainChain = pass.catch(() => {});
		return pass;
	}
	async drainPass() {
		for (const state of await listSpaceStates()) {
			if (state.role === "reader") continue;
			for (const entry of await listOutboxBySpace(state.id)) try {
				await this.pushEntry(state, entry);
			} catch (error) {
				this.emit("error", {
					kind: "push",
					itemId: entry.id,
					error
				});
				break;
			}
		}
	}
	async pushEntry(state, entry) {
		let current = entry;
		for (let attempt = 0; attempt < MAX_PUSH_RETRIES; attempt++) {
			const header = {
				itemId: current.id,
				keyEpoch: state.keyEpoch,
				schemaVer: 1,
				baseSeq: current.baseSeq,
				deleted: current.deleted
			};
			const plaintext = current.deleted ? /* @__PURE__ */ new Uint8Array(0) : encodeRow(current.data);
			const sealed = await this.deps.crypto.spaceEncrypt(COLLECTION$1, state.id, header, plaintext);
			const result = await this.deps.sync.push(state.id, {
				itemId: current.id,
				baseSeq: current.baseSeq,
				keyEpoch: state.keyEpoch,
				schemaVer: 1,
				deleted: current.deleted,
				blob: current.deleted ? "" : bytesToBase64(sealed.blob),
				sig: sealed.sig
			});
			if (result.status === "ok") {
				const local = await getContact(current.id);
				if (local) await putContact({
					...local,
					seq: result.seq,
					keyEpoch: state.keyEpoch
				});
				await deleteOutbox(current.id);
				return;
			}
			if (result.status === "stale_epoch") {
				state = {
					...state,
					keyEpoch: result.currentEpoch
				};
				await putSpaceState(state);
				continue;
			}
			const merged = await this.rebaseOnRemote(state, current, result.current);
			if (!merged) return;
			current = merged;
		}
		this.emit("error", {
			kind: "push",
			itemId: current.id,
			error: "push retries exhausted"
		});
	}
	/**
	* Conflict path: decrypt the server's current row, merge on device, rebase the
	* outbox entry. Returns null when the remote wins outright (tombstone or an
	* unreadable row), in which case the local write is dropped.
	*/
	async rebaseOnRemote(state, current, remote) {
		const [rowForDecrypt] = await this.toDecryptRows([remote]);
		const remotePlain = (await this.deps.crypto.spaceDecryptBatch(COLLECTION$1, state.id, [{
			header: rowForDecrypt.header,
			blob: rowForDecrypt.blob
		}]))[0];
		if (!remotePlain || remotePlain.error !== void 0 || remote.deleted) {
			await deleteOutbox(current.id);
			this.emit("changed");
			return null;
		}
		const merged = mergeContacts({
			data: current.data,
			updatedAt: current.updatedAt,
			authorId: this.deps.ownUserId,
			seq: current.baseSeq
		}, {
			data: decodeRow(remotePlain.plaintext),
			updatedAt: remote.updated_at,
			authorId: remote.author_id,
			seq: remote.seq
		});
		const rebased = {
			...current,
			data: merged,
			baseSeq: remote.seq,
			attempts: current.attempts + 1
		};
		await putOutbox(rebased);
		return rebased;
	}
};
//#endregion
//#region src/vault/spaces.ts
var VaultSpaces = class {
	constructor(api, crypto, collection, ownUserId) {
		this.api = api;
		this.crypto = crypto;
		this.collection = collection;
		this.ownUserId = ownUserId;
		this.signerPubCache = /* @__PURE__ */ new Map();
	}
	async list() {
		return (await this.api.json("GET", `/api/v1/spaces?collection=${encodeURIComponent(this.collection)}`)).spaces;
	}
	/** Returns the personal space, creating it on first run. */
	async ensurePersonal() {
		const personal = (await this.list()).find((membership) => membership.space.kind === "personal");
		if (personal) {
			await this.unlock(personal);
			return personal;
		}
		return this.createPersonal();
	}
	/**
	* Unwraps + pins every membership's keys and auto-accepts fresh invites. A pin
	* mismatch comes back as ok:false — that space must not sync, its key material
	* changed underneath us.
	*/
	async unlockAll() {
		const memberships = await this.list();
		const results = [];
		for (const membership of memberships) try {
			await this.unlock(membership);
			if (membership.member.status === "invited") await this.accept(membership);
			results.push({
				spaceId: membership.space.space_id,
				ok: true
			});
		} catch (error) {
			results.push({
				spaceId: membership.space.space_id,
				ok: false,
				error: error instanceof Error ? error.message : String(error)
			});
		}
		return results;
	}
	/** Published Ed25519 signing key of an author, for envelope verification. */
	async signerPubFor(userId) {
		const cached = this.signerPubCache.get(userId);
		if (cached) return cached;
		const directory = await this.lookupDirectory(userId);
		this.signerPubCache.set(userId, directory.sign_public_key);
		return directory.sign_public_key;
	}
	async createPersonal() {
		const spaceId = crypto.randomUUID();
		const minted = await this.crypto.spaceKeyCreate(this.collection, spaceId, this.ownUserId);
		const membership = await this.api.json("POST", "/api/v1/spaces", JSON.stringify({
			space_id: spaceId,
			collection: this.collection,
			kind: "personal",
			wrapped_key: minted.wrappedKey,
			signature: minted.signature
		}));
		if (membership.space.space_id !== spaceId) await this.unlock(membership);
		return membership;
	}
	async unlock(membership) {
		for (const wrap of membership.member.wrapped_keys ?? []) await this.crypto.spaceKeyUnwrap(this.collection, membership.space.space_id, {
			keyEpoch: wrap.epoch,
			wrappedKey: wrap.wrapped_key,
			signature: wrap.signature,
			signerPub: await this.signerPubFor(membership.member.added_by_id),
			userId: this.ownUserId,
			inviterUserId: membership.member.added_by_id
		});
	}
	async accept(membership) {
		const wraps = membership.member.wrapped_keys ?? [];
		const newest = wraps[wraps.length - 1];
		if (!newest) throw new Error("invite has no wrapped keys");
		const unwrapped = await this.crypto.spaceKeyUnwrap(this.collection, membership.space.space_id, {
			keyEpoch: newest.epoch,
			wrappedKey: newest.wrapped_key,
			signature: newest.signature,
			signerPub: await this.signerPubFor(membership.member.added_by_id),
			userId: this.ownUserId,
			inviterUserId: membership.member.added_by_id
		});
		const response = await this.api.request("POST", `/api/v1/spaces/${membership.space.space_id}/accept`, JSON.stringify({ accept_signature: unwrapped.mySignature }));
		if (!response.ok) throw new Error(`accept failed: ${response.status}`);
	}
	async lookupDirectory(userId) {
		const params = new URLSearchParams({
			scope: this.collection,
			user: userId
		});
		return this.api.json("GET", `/api/v1/keys/public?${params}`);
	}
};
//#endregion
//#region src/resources/sync.ts
/** Thrown when the pull cursor predates the tombstone purge horizon — the
* local store must be wiped and re-synced from zero. */
var CursorPurgedError = class extends Error {
	constructor() {
		super("sync cursor purged — full resync required");
		this.name = "CursorPurgedError";
	}
};
//#endregion
//#region src/vault/sync.ts
var VaultSync = class {
	constructor(api) {
		this.api = api;
	}
	async pull(spaceId, since, limit = 500) {
		const params = new URLSearchParams({
			since: String(since),
			limit: String(limit)
		});
		const response = await this.api.request("GET", `/api/v1/spaces/${spaceId}/items?${params}`);
		if (response.status === 410) throw new CursorPurgedError();
		if (!response.ok) throw new Error(`sync pull failed: ${response.status}`);
		return await response.json();
	}
	/** Writes one envelope; conflicts come back as data, not exceptions. */
	async push(spaceId, envelope) {
		const response = await this.api.request("PUT", `/api/v1/spaces/${spaceId}/items/${envelope.itemId}`, JSON.stringify({
			base_seq: envelope.baseSeq,
			key_epoch: envelope.keyEpoch,
			schema_ver: envelope.schemaVer,
			deleted: envelope.deleted,
			blob: envelope.blob,
			sig: envelope.sig
		}));
		if (response.ok) {
			const body = await response.json();
			return {
				status: "ok",
				seq: body.seq,
				keyEpoch: body.key_epoch
			};
		}
		if (response.status === 409) {
			const body = await response.json();
			if (body.error === "stale_epoch") return {
				status: "stale_epoch",
				currentEpoch: body.current_epoch ?? 0
			};
			if (body.current) return {
				status: "conflict",
				current: body.current
			};
		}
		throw new Error(`sync push failed: ${response.status}`);
	}
	/** Encrypted version history of one item, oldest first. */
	async versions(spaceId, itemId) {
		return (await this.api.json("GET", `/api/v1/spaces/${spaceId}/items/${itemId}/versions`)).versions;
	}
};
//#endregion
//#region src/vault/host.ts
var COLLECTION = "contacts";
function createContactsVault(options) {
	const api = new ApiClient({
		apiUrl: options.apiUrl,
		getToken: options.getToken,
		refreshToken: options.refreshToken
	});
	const engine = new ContactsEngine({
		spaces: new VaultSpaces(api, options.crypto, COLLECTION, options.ownUserId),
		sync: new VaultSync(api),
		crypto: options.crypto,
		ownUserId: options.ownUserId
	});
	engine.on("changed", () => options.emit("changed"));
	engine.on("progress", (detail) => options.emit("progress", detail));
	engine.on("error", (detail) => options.emit("error", detail));
	let startPromise = null;
	function start(pollIntervalMs) {
		if (!startPromise) startPromise = engine.start(pollIntervalMs).catch((error) => {
			startPromise = null;
			throw error;
		});
		return startPromise;
	}
	async function handle(message) {
		switch (message.type) {
			case "contacts-start":
				await start(typeof message.pollIntervalMs === "number" ? message.pollIntervalMs : 3e4);
				return { started: true };
			case "contacts-stop":
				engine.stop();
				startPromise = null;
				return { stopped: true };
			case "contacts-sync":
				await engine.syncOnce();
				return { synced: true };
			case "contacts-list": {
				const result = await engine.list(queryOf(message));
				return {
					items: result.items,
					total: result.total
				};
			}
			case "contacts-count": return { count: await engine.count(queryOf(message)) };
			case "contacts-get": return { item: await engine.get(String(message.id)) };
			case "contacts-write": {
				const spaceId = typeof message.spaceId === "string" ? message.spaceId : void 0;
				return { id: await engine.write(message.contact, spaceId) };
			}
			case "contacts-trash":
				await engine.trash(String(message.id));
				return { trashed: true };
			case "contacts-history": return { versions: await engine.history(String(message.id)) };
			default: throw new Error(`unknown contacts op: ${String(message.type)}`);
		}
	}
	return { handle };
}
function queryOf(message) {
	const query = message.query;
	if (!query || typeof query !== "object") return {};
	return query;
}
//#endregion
//#region src/vault/protocol.ts
/** Ops that mutate data need a write-implying grant (contacts:write / :admin). */
var WRITE_OPS = /* @__PURE__ */ new Set(["contacts-write", "contacts-trash"]);
function isContactsOp(type) {
	return type.startsWith("contacts-");
}
/**
* Start and sync stay read ops — pulling is reading, and a read-only client must
* still be able to refresh what it is allowed to see.
*/
function contactsOpNeedsWrite(type) {
	return WRITE_OPS.has(type);
}
//#endregion
//#region src/vault/index.ts
if (typeof window !== "undefined") {
	window.__createContactsVault = createContactsVault;
	window.__contactsOpNeedsWrite = contactsOpNeedsWrite;
	window.__isContactsOp = isContactsOp;
}
//#endregion
export { contactsOpNeedsWrite, createContactsVault, isContactsOp };

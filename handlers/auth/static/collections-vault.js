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
var DB_VERSION = 1;
function requestToPromise(request) {
	return new Promise((resolve, reject) => {
		request.onsuccess = () => resolve(request.result);
		request.onerror = () => reject(request.error);
	});
}
/** Every open database, so the test hook can drop them all. */
var connections = /* @__PURE__ */ new Map();
var CollectionDb = class {
	constructor(collection) {
		this.name = `neoworks-vault-${collection}`;
	}
	open() {
		const existing = connections.get(this.name);
		if (existing) return existing;
		const opening = new Promise((resolve, reject) => {
			const req = indexedDB.open(this.name, DB_VERSION);
			req.onupgradeneeded = () => {
				const db = req.result;
				db.createObjectStore("items", { keyPath: "id" }).createIndex("bySpace", "spaceId");
				db.createObjectStore("outbox", { keyPath: "id" }).createIndex("bySpace", "spaceId");
				db.createObjectStore("spaces", { keyPath: "id" });
				db.createObjectStore("meta");
			};
			req.onsuccess = () => resolve(req.result);
			req.onerror = () => reject(req.error);
		});
		connections.set(this.name, opening);
		return opening;
	}
	async store(name, mode) {
		return (await this.open()).transaction(name, mode).objectStore(name);
	}
	async putItem(row) {
		await requestToPromise((await this.store("items", "readwrite")).put(row));
	}
	/** Applies a whole pulled page in one transaction. */
	async putItems(rows) {
		if (rows.length === 0) return;
		const db = await this.open();
		return new Promise((resolve, reject) => {
			const tx = db.transaction("items", "readwrite");
			const items = tx.objectStore("items");
			for (const row of rows) items.put(row);
			tx.oncomplete = () => resolve();
			tx.onerror = () => reject(tx.error);
		});
	}
	async getItem(id) {
		return await requestToPromise((await this.store("items", "readonly")).get(id)) ?? null;
	}
	async listItems() {
		return requestToPromise((await this.store("items", "readonly")).getAll());
	}
	async listItemsBySpace(spaceId) {
		return requestToPromise((await this.store("items", "readonly")).index("bySpace").getAll(spaceId));
	}
	async deleteItem(id) {
		await requestToPromise((await this.store("items", "readwrite")).delete(id));
	}
	async putOutbox(entry) {
		await requestToPromise((await this.store("outbox", "readwrite")).put(entry));
	}
	async getOutbox(id) {
		return await requestToPromise((await this.store("outbox", "readonly")).get(id)) ?? null;
	}
	async listOutboxBySpace(spaceId) {
		return requestToPromise((await this.store("outbox", "readonly")).index("bySpace").getAll(spaceId));
	}
	async deleteOutbox(id) {
		await requestToPromise((await this.store("outbox", "readwrite")).delete(id));
	}
	async putSpaceState(state) {
		await requestToPromise((await this.store("spaces", "readwrite")).put(state));
	}
	async getSpaceState(id) {
		return await requestToPromise((await this.store("spaces", "readonly")).get(id)) ?? null;
	}
	async listSpaceStates() {
		return requestToPromise((await this.store("spaces", "readonly")).getAll());
	}
	async getMeta(key) {
		return await requestToPromise((await this.store("meta", "readonly")).get(key)) ?? null;
	}
	async setMeta(key, value) {
		await requestToPromise((await this.store("meta", "readwrite")).put(value, key));
	}
	/** Wipes one space's rows + cursor (410 cursor_purged → full resync). */
	async wipeSpace(spaceId) {
		const rows = await this.listItemsBySpace(spaceId);
		const db = await this.open();
		await new Promise((resolve, reject) => {
			const tx = db.transaction(["items", "spaces"], "readwrite");
			const items = tx.objectStore("items");
			for (const row of rows) items.delete(row.id);
			tx.oncomplete = () => resolve();
			tx.onerror = () => reject(tx.error);
		});
		const state = await this.getSpaceState(spaceId);
		if (state) await this.putSpaceState({
			...state,
			cursor: 0
		});
	}
};
//#endregion
//#region src/vault/envelope.ts
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
		versionId: envelope.version_id ?? "",
		createdAt: envelope.created_at,
		updatedAt: envelope.updated_at,
		data
	};
}
//#endregion
//#region src/vault/query/operators.ts
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
	const absent = point === void 0 || point === null;
	if (filter.isNull !== void 0 && filter.isNull !== absent) return false;
	if (filter.within) return false;
	if (!filter.near) return true;
	if (absent) return false;
	return haversineMeters(point, filter.near) <= filter.near.radiusMeters;
}
function list(value) {
	if (!value) return [];
	return [...value];
}
//#endregion
//#region src/vault/query/engine.ts
/** The and/or/not keys every generated filter carries. */
var TREE_KEYS = /* @__PURE__ */ new Set([
	"and",
	"or",
	"not"
]);
/** Evaluates a filter tree against one decrypted row. */
function matchesFilter(row, filter, fields) {
	if (!filter || typeof filter !== "object") return true;
	const tree = filter;
	if (tree.and && !tree.and.every((sub) => matchesFilter(row, sub, fields))) return false;
	if (tree.or && !tree.or.some((sub) => matchesFilter(row, sub, fields))) return false;
	if (tree.not && matchesFilter(row, tree.not, fields)) return false;
	for (const [key, condition] of Object.entries(tree)) {
		if (TREE_KEYS.has(key)) continue;
		if (condition === void 0 || condition === null) continue;
		if (!matchesField(row, key, condition, fields)) return false;
	}
	return true;
}
function matchesField(row, key, condition, fields) {
	const rule = fields[key];
	if (!rule) return false;
	switch (rule.kind) {
		case "string": return matchString(rule.get(row), condition);
		case "bool": return matchBool(rule.get(row), condition);
		case "int": return matchInt(rule.get(row) ?? 0, condition);
		case "date": return matchDate(rule.get(row), condition);
		case "stringList": return matchStringList(list(rule.get(row)), condition);
		case "fieldList": return matchFieldList(list(rule.get(row)), condition);
		case "geo": return matchGeo(rule.get(row), condition);
	}
}
/** Case-insensitive needle over the collection's declared search fields. */
function matchesSearch(row, needle, searchText) {
	const text = needle.toLowerCase();
	return searchText(row).some((value) => lower(value).includes(text));
}
/** Applies sort keys in order, falling back to the collection's default. */
function sortRows(rows, sort, pick, comparators, defaultSort) {
	const keys = sort && sort.length > 0 ? sort : defaultSort;
	const sorted = [...rows];
	sorted.sort((left, right) => {
		for (const key of keys) {
			const comparator = comparators[key.field];
			if (!comparator) continue;
			const direction = key.direction === "DESC" ? -1 : 1;
			const comparison = comparator(pick(left), pick(right));
			if (comparison !== 0) return comparison * direction;
		}
		return 0;
	});
	return sorted;
}
/** Compares two ISO date strings, treating absent as epoch. */
function compareDates(left, right) {
	return new Date(left ?? 0).getTime() - new Date(right ?? 0).getTime();
}
/** Compares two strings case-insensitively, treating absent as empty. */
function compareText(left, right) {
	return (left ?? "").localeCompare(right ?? "", void 0, { sensitivity: "base" });
}
/** True when the row passes scope, the collection's extras, search and filter. */
function matchesQuery(spec, row, options) {
	if (!spec.matchesScope(row, options.scope)) return false;
	if (spec.matchesExtras && !spec.matchesExtras(row, options)) return false;
	const needle = (options.search ?? "").trim();
	if (needle.length > 0 && !matchesSearch(row, needle, spec.searchText)) return false;
	if (options.filter && !matchesFilter(row, options.filter, spec.fields)) return false;
	return true;
}
/**
* Ranking first (semantic search), then sort keys. A collection that ranks
* returns its own order, which an explicit sort from the caller still overrides.
*/
function orderRows(spec, items, options, pick) {
	const ranked = spec.rank?.(items.map(pick), options);
	if (ranked && !options.sort) {
		const byId = new Map(items.map((item) => [pick(item).id, item]));
		return ranked.map((row) => byId.get(row.id)).filter((item) => item !== void 0);
	}
	return sortRows(items, options.sort, pick, spec.comparators, spec.defaultSort);
}
//#endregion
//#region src/vault/engine.ts
var PULL_PAGE = 500;
var MAX_PUSH_RETRIES = 5;
/**
* Local-first store + sync loop. Reads always come from IndexedDB; writes land
* locally (optimistic) plus in the outbox, then push in the background.
*/
var CollectionEngine = class {
	constructor(deps) {
		this.deps = deps;
		this.listeners = /* @__PURE__ */ new Map();
		this.pollTimer = null;
		this.drainChain = Promise.resolve();
		this.personalSpaceId = null;
		this.started = false;
		this.collection = deps.collection;
		this.db = new CollectionDb(deps.collection.name);
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
			const existing = await this.db.getSpaceState(membership.space.space_id);
			await this.db.putSpaceState({
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
			for (const state of await this.db.listSpaceStates()) await this.pullSpace(state.id);
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
		const sorted = orderRows(this.collection, matched, options, (item) => item.data);
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
	* Rows passing the query. Envelope tombstones (`row.deleted` on the local row)
	* are gone for good and never surface in any scope — the restorable trash is
	* the codec payload's own `deleted` flag, which the scope filter handles.
	*/
	async matchingRows(options) {
		return (await this.db.listItems()).filter((row) => !row.deleted && matchesQuery(this.collection, row.data, options));
	}
	async get(id) {
		return this.db.getItem(id);
	}
	/**
	* Decrypted version history of one row, oldest first. Server-side rows are
	* ciphertext copies made on every update; they decrypt with the same per-epoch
	* space keys.
	*/
	async history(id) {
		const local = await this.db.getItem(id);
		if (!local) return [];
		const readable = (await this.deps.sync.versions(local.spaceId, id)).filter((version) => version.blob);
		const rows = await this.toDecryptVersions(readable);
		const decrypted = await this.deps.crypto.spaceDecryptBatch(this.collection.name, local.spaceId, rows.map((row) => ({
			header: row.header,
			blob: row.blob
		})));
		const out = [];
		for (let i = 0; i < rows.length; i++) {
			const result = decrypted[i];
			if (result.error !== void 0) continue;
			const version = rows[i].version;
			const data = this.collection.decodeVersion(result.plaintext);
			out.push({
				versionId: version.version_id,
				parentIds: data.parent_ids ?? [],
				seq: version.seq,
				createdAt: version.created_at,
				authorId: version.author_id,
				data
			});
		}
		return out;
	}
	/**
	* Creates or updates a row. Returns its id. The caller may pass a partial row:
	* an absent `id` mints a new one, and the collection's own defaults (uid,
	* timestamps, flags) are filled by its spec rather than by every app.
	*/
	async write(input, spaceId) {
		const existing = input.id ? await this.db.getItem(input.id) : null;
		const id = existing?.id ?? (input.id || crypto.randomUUID());
		const targetSpace = existing?.spaceId ?? spaceId ?? this.personalSpaceId;
		if (!targetSpace) throw new Error("no space available — call start() first");
		const now = (/* @__PURE__ */ new Date()).toISOString();
		const data = this.collection.prepare(input, existing?.data ?? null, id, now);
		const state = await this.db.getSpaceState(targetSpace);
		const version = this.mintVersion(data, parentsOf(existing), now);
		await this.db.putItem({
			id,
			spaceId: targetSpace,
			seq: existing?.seq ?? 0,
			keyEpoch: state?.keyEpoch ?? 1,
			schemaVer: 1,
			deleted: false,
			authorId: this.deps.ownUserId,
			versionId: version.versionId,
			createdAt: data.created_at,
			updatedAt: now,
			data
		});
		await this.db.putOutbox({
			id,
			spaceId: targetSpace,
			baseSeq: existing?.seq ?? 0,
			deleted: false,
			data,
			updatedAt: now,
			attempts: 0,
			versions: [version]
		});
		this.emit("changed");
		this.drainOutbox();
		return id;
	}
	/**
	* Branches from an earlier version: its content becomes the new head, and the
	* lineage forks at that version rather than continuing the chain.
	*/
	async restoreVersion(id, versionId) {
		const local = await this.db.getItem(id);
		if (!local) throw new Error("row not found");
		const target = (await this.history(id)).find((entry) => entry.versionId === versionId);
		if (!target) throw new Error("version not found");
		const now = (/* @__PURE__ */ new Date()).toISOString();
		const data = {
			...local.data,
			...this.collection.rowFieldsOf(target.data),
			id,
			updated_at: now
		};
		const version = this.mintVersion(data, [versionId], now);
		await this.db.putItem({
			...local,
			data,
			versionId: version.versionId,
			updatedAt: now
		});
		await this.db.putOutbox({
			id,
			spaceId: local.spaceId,
			baseSeq: local.seq,
			deleted: false,
			data,
			updatedAt: now,
			attempts: 0,
			versions: [version]
		});
		this.emit("changed");
		this.drainOutbox();
	}
	mintVersion(data, parentIds, createdAt) {
		const versionId = crypto.randomUUID();
		return {
			versionId,
			data: this.collection.versionOf(versionId, data, parentIds, createdAt)
		};
	}
	/** Tombstones a row (server drops the ciphertext). */
	async trash(id) {
		const existing = await this.db.getItem(id);
		if (!existing) return;
		const now = (/* @__PURE__ */ new Date()).toISOString();
		await this.db.putItem({
			...existing,
			deleted: true,
			updatedAt: now
		});
		await this.db.putOutbox({
			id,
			spaceId: existing.spaceId,
			baseSeq: existing.seq,
			deleted: true,
			data: existing.data,
			updatedAt: now,
			attempts: 0,
			versions: []
		});
		this.emit("changed");
		this.drainOutbox();
	}
	async pullSpace(spaceId) {
		let state = await this.db.getSpaceState(spaceId);
		if (!state) return;
		let cursor = state.cursor;
		for (;;) {
			let page;
			try {
				page = await this.deps.sync.pull(spaceId, cursor, PULL_PAGE);
			} catch (error) {
				if (error.name === "CursorPurgedError") {
					await this.db.wipeSpace(spaceId);
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
			await this.db.putSpaceState({
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
	/** Same shape as toDecryptRows, but bound to each entry's own version id. */
	async toDecryptVersions(versions) {
		return Promise.all(versions.map(async (version) => ({
			version,
			header: {
				itemId: version.item_id,
				versionId: version.version_id,
				keyEpoch: version.key_epoch,
				schemaVer: version.schema_ver,
				baseSeq: version.base_seq,
				deleted: version.deleted,
				sig: version.sig ?? "",
				signerPub: await this.deps.spaces.signerPubFor(version.author_id),
				authorUserId: version.author_id
			},
			blob: version.blob ? base64ToBytes(version.blob) : /* @__PURE__ */ new Uint8Array(0)
		})));
	}
	async applyEnvelopes(spaceId, envelopes) {
		const rows = await this.toDecryptRows(envelopes);
		const decrypted = await this.deps.crypto.spaceDecryptBatch(this.collection.name, spaceId, rows.map((row) => ({
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
			if (await this.db.getOutbox(envelope.item_id)) continue;
			const local = await this.db.getItem(envelope.item_id);
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
			toStore.push(wireToLocal(envelope, this.collection.decodeRow(result.plaintext)));
		}
		await this.db.putItems(toStore);
	}
	drainOutbox() {
		const pass = this.drainChain.then(() => this.drainPass());
		this.drainChain = pass.catch(() => {});
		return pass;
	}
	async drainPass() {
		for (const state of await this.db.listSpaceStates()) {
			if (state.role === "reader") continue;
			for (const entry of await this.db.listOutboxBySpace(state.id)) try {
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
			const plaintext = current.deleted ? /* @__PURE__ */ new Uint8Array(0) : this.collection.encodeRow(current.data);
			const sealed = await this.deps.crypto.spaceEncrypt(this.collection.name, state.id, header, plaintext);
			const versions = await this.sealVersions(state, current);
			const result = await this.deps.sync.push(state.id, {
				itemId: current.id,
				baseSeq: current.baseSeq,
				keyEpoch: state.keyEpoch,
				schemaVer: 1,
				deleted: current.deleted,
				blob: current.deleted ? "" : bytesToBase64(sealed.blob),
				sig: sealed.sig,
				versions
			});
			if (result.status === "ok") {
				const local = await this.db.getItem(current.id);
				const head = current.versions[current.versions.length - 1];
				if (local) await this.db.putItem({
					...local,
					seq: result.seq,
					keyEpoch: state.keyEpoch,
					versionId: head ? head.versionId : local.versionId
				});
				await this.db.deleteOutbox(current.id);
				return;
			}
			if (result.status === "stale_epoch") {
				state = {
					...state,
					keyEpoch: result.currentEpoch
				};
				await this.db.putSpaceState(state);
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
	/** Each history entry is sealed under its own version-bound key and AAD. */
	async sealVersions(state, entry) {
		const sealed = [];
		for (const version of entry.versions) {
			const header = {
				itemId: entry.id,
				versionId: version.versionId,
				keyEpoch: state.keyEpoch,
				schemaVer: 1,
				baseSeq: entry.baseSeq,
				deleted: false
			};
			const row = await this.deps.crypto.spaceEncrypt(this.collection.name, state.id, header, this.collection.encodeVersion(version.data));
			sealed.push({
				versionId: version.versionId,
				blob: bytesToBase64(row.blob),
				sig: row.sig
			});
		}
		return sealed;
	}
	/**
	* Conflict path: decrypt the server's current row, merge on device, rebase the
	* outbox entry. Returns null when the remote wins outright (tombstone or an
	* unreadable row), in which case the local write is dropped.
	*/
	async rebaseOnRemote(state, current, remote) {
		const [rowForDecrypt] = await this.toDecryptRows([remote]);
		const remotePlain = (await this.deps.crypto.spaceDecryptBatch(this.collection.name, state.id, [{
			header: rowForDecrypt.header,
			blob: rowForDecrypt.blob
		}]))[0];
		if (!remotePlain || remotePlain.error !== void 0 || remote.deleted) {
			await this.db.deleteOutbox(current.id);
			this.emit("changed");
			return null;
		}
		const merged = this.collection.merge({
			data: current.data,
			updatedAt: current.updatedAt,
			authorId: this.deps.ownUserId,
			seq: current.baseSeq
		}, {
			data: this.collection.decodeRow(remotePlain.plaintext),
			updatedAt: remote.updated_at,
			authorId: remote.author_id,
			seq: remote.seq
		});
		const branch = current.versions[0];
		const parents = [remote.version_id, branch?.versionId].filter((id) => typeof id === "string" && id.length > 0);
		const mergeVersion = this.mintVersion(merged, parents, (/* @__PURE__ */ new Date()).toISOString());
		const rebased = {
			...current,
			data: merged,
			baseSeq: remote.seq,
			attempts: current.attempts + 1,
			versions: branch ? [branch, mergeVersion] : [mergeVersion]
		};
		await this.db.putOutbox(rebased);
		return rebased;
	}
};
function parentsOf(existing) {
	if (!existing || !existing.versionId) return [];
	return [existing.versionId];
}
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
			sig: envelope.sig,
			versions: envelope.versions.map((version) => ({
				version_id: version.versionId,
				blob: version.blob,
				sig: version.sig
			}))
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
/** Guards against a hostile buffer driving unbounded recursion. */
var MAX_DEPTH$2 = 100;
/** Above this a double can no longer represent every integer exactly. */
var MAX_SAFE$2 = 9007199254740991;
var TWO_TO_32$2 = 4294967296;
var CodecError$2 = class extends Error {
	constructor(code, path, message) {
		super(path.length > 0 ? path + ": " + message : message);
		this.code = code;
		this.path = path;
		this.name = "CodecError";
	}
};
var textEncoder$2 = new TextEncoder();
var textDecoder$2 = new TextDecoder("utf-8", { fatal: true });
function isSurrogatePair$2(value, index) {
	if ((value.charCodeAt(index) & 64512) !== 55296) return false;
	return (value.charCodeAt(index + 1) & 64512) === 56320;
}
function utf8Length$2(value) {
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
		if (isSurrogatePair$2(value, index)) {
			length += 4;
			index++;
			continue;
		}
		length += 3;
	}
	return length;
}
/** The caller has already reserved utf8Length(value) bytes at offset. */
function writeUtf8$2(bytes, offset, value) {
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
		if (isSurrogatePair$2(value, index)) {
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
function varintWidth$2(value) {
	if (value < 128) return 1;
	if (value < 16384) return 2;
	if (value < 2097152) return 3;
	if (value < 268435456) return 4;
	return 5;
}
function writeVarintAt$2(bytes, offset, value) {
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
var pooledBuffer$2 = null;
/** Rows larger than this are rare enough that retaining the buffer is waste. */
var MAX_POOLED_CAPACITY$2 = 65536;
var Writer$2 = class {
	constructor(capacity = 256) {
		this.view = null;
		this.length = 0;
		if (pooledBuffer$2 !== null && pooledBuffer$2.length >= capacity) {
			this.bytes = pooledBuffer$2;
			pooledBuffer$2 = null;
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
		const byteLength = utf8Length$2(value);
		this.varintNumber(byteLength);
		this.reserve(byteLength);
		writeUtf8$2(this.bytes, this.length, value);
		this.length += byteLength;
	}
	longString(value) {
		const lengthOffset = this.beginLengthDelimited();
		this.reserve(value.length * 3);
		const written = textEncoder$2.encodeInto(value, this.bytes.subarray(this.length)).written;
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
		const width = varintWidth$2(bodyLength);
		if (width > 1) {
			this.reserve(width - 1);
			this.bytes.copyWithin(bodyStart + width - 1, bodyStart, this.length);
			this.length += width - 1;
		}
		writeVarintAt$2(this.bytes, lengthOffset, bodyLength);
	}
	finish() {
		const result = this.bytes.slice(0, this.length);
		if (this.bytes.length <= MAX_POOLED_CAPACITY$2 && (pooledBuffer$2 === null || pooledBuffer$2.length < this.bytes.length)) pooledBuffer$2 = this.bytes;
		return result;
	}
};
/** Shared float conversion area \u2014 cheaper than a DataView per read. */
var scratchBytes$2 = /* @__PURE__ */ new Uint8Array(8);
var scratchView$2 = new DataView(scratchBytes$2.buffer);
function copyToScratch$2(buffer, position, count) {
	for (let index = 0; index < count; index++) scratchBytes$2[index] = buffer[position + index];
}
/**
* null when any byte is non-ASCII; the caller falls back to TextDecoder.
* Rope concatenation measures faster here than fromCharCode.apply and than
* TextDecoder itself for the short fields that dominate real rows.
*/
function asciiString$2(buffer, start, length) {
	const end = start + length;
	for (let index = start; index < end; index++) if (buffer[index] > 127) return null;
	let out = "";
	for (let index = start; index < end; index++) out += String.fromCharCode(buffer[index]);
	return out;
}
var Reader$2 = class Reader$2 {
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
		return new Reader$2(bytes, 0, bytes.length, 0, path);
	}
	hasMore() {
		return this.position < this.end;
	}
	require(count) {
		if (this.position + count > this.end) throw new CodecError$2("TRUNCATED", this.path, "buffer ended mid-value");
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
		throw new CodecError$2("OVERLONG_VARINT", this.path, "varint exceeds 10 bytes");
	}
	commitVarint(position, lo, hi) {
		this.position = position;
		this.lo = lo >>> 0;
		this.hi = hi >>> 0;
	}
	truncated() {
		return new CodecError$2("TRUNCATED", this.path, "buffer ended mid-value");
	}
	/** The raw 64-bit value, unsigned. Only for i64/u64/duration. */
	varint() {
		this.readVarint64();
		if (this.hi === 0) return BigInt(this.lo);
		return BigInt(this.hi) << 32n | BigInt(this.lo);
	}
	varintUnsigned(path) {
		this.readVarint64();
		return unsignedFromHalves$2(this.lo, this.hi, path);
	}
	varintSigned(path) {
		this.readVarint64();
		return signedFromHalves$2(this.lo, this.hi, path);
	}
	skipVarint() {
		this.readVarint64();
	}
	key() {
		this.readVarint64();
		if (this.hi !== 0) throw new CodecError$2("BAD_TAG", this.path, "wire key exceeds 32 bits");
		return this.lo;
	}
	/** A length prefix: non-negative and inside the remaining buffer. */
	length() {
		this.readVarint64();
		const value = unsignedFromHalves$2(this.lo, this.hi, this.path);
		if (this.position + value > this.end) throw new CodecError$2("TRUNCATED", this.path, "length-delimited field runs past the buffer");
		return value;
	}
	double() {
		this.require(8);
		copyToScratch$2(this.buffer, this.position, 8);
		this.position += 8;
		return scratchView$2.getFloat64(0, true);
	}
	float32() {
		this.require(4);
		copyToScratch$2(this.buffer, this.position, 4);
		this.position += 4;
		return scratchView$2.getFloat32(0, true);
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
		if (this.depth + 1 > MAX_DEPTH$2) throw new CodecError$2("DEPTH", path, "message nesting exceeds 100");
		const length = this.length();
		const start = this.position;
		this.position += length;
		return new Reader$2(this.buffer, start, start + length, this.depth + 1, path);
	}
	/** A bounded Reader over a packed repeated body. */
	packed(path) {
		const length = this.length();
		const start = this.position;
		this.position += length;
		return new Reader$2(this.buffer, start, start + length, this.depth, path);
	}
	string() {
		const length = this.length();
		const start = this.position;
		this.position += length;
		if (length <= 64) {
			const ascii = asciiString$2(this.buffer, start, length);
			if (ascii !== null) return ascii;
		}
		try {
			return textDecoder$2.decode(this.buffer.subarray(start, start + length));
		} catch {
			throw new CodecError$2("BAD_UTF8", this.path, "field is not valid UTF-8");
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
		const keyWidth = varintWidth$2(key);
		const raw = new Uint8Array(keyWidth + bodyLength);
		writeVarintAt$2(raw, 0, key);
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
		throw new CodecError$2("BAD_WIRE_TYPE", this.path, "unsupported wire type " + wire);
	}
};
function unsignedFromHalves$2(lo, hi, path) {
	if (hi > 2097151) throw new CodecError$2("PRECISION", path, "integer exceeds the safe range for a JS number");
	return hi * TWO_TO_32$2 + lo;
}
function signedFromHalves$2(lo, hi, path) {
	if ((hi & 2147483648) === 0) return unsignedFromHalves$2(lo, hi, path);
	let negatedLo = ~lo + 1 >>> 0;
	let negatedHi = ~hi >>> 0;
	if (negatedLo === 0) negatedHi = negatedHi + 1 >>> 0;
	const magnitude = negatedHi * TWO_TO_32$2 + negatedLo;
	if (magnitude > MAX_SAFE$2) throw new CodecError$2("PRECISION", path, "integer exceeds the safe range for a JS number");
	return -magnitude;
}
function requireInteger$2(value, path) {
	if (!Number.isFinite(value)) throw new CodecError$2("RANGE", path, "value is not finite");
	if (!Number.isInteger(value)) throw new CodecError$2("RANGE", path, "value is not an integer");
	return value;
}
function requireFinite$1(value, path) {
	if (typeof value !== "number") throw new CodecError$2("TYPE", path, "expected a number");
	return value;
}
var HEX$2 = "0123456789abcdef";
/** 512 two-character strings, so formatting a uuid is 16 lookups and a join. */
var HEX_PAIRS$2 = (() => {
	const pairs = new Array(256);
	for (let i = 0; i < 256; i++) pairs[i] = HEX$2[i >> 4] + HEX$2[i & 15];
	return pairs;
})();
/** -1 for any character that is not a hex digit. */
var HEX_VALUES$2 = (() => {
	const values = (/* @__PURE__ */ new Int8Array(128)).fill(-1);
	for (let i = 0; i < 16; i++) {
		values[HEX$2.charCodeAt(i)] = i;
		values["0123456789ABCDEF".charCodeAt(i)] = i;
	}
	return values;
})();
function uuidToBytes$2(value, path) {
	const out = /* @__PURE__ */ new Uint8Array(16);
	let written = 0;
	let high = -1;
	for (let index = 0; index < value.length; index++) {
		const code = value.charCodeAt(index);
		if (code === 45) continue;
		const digit = code < 128 ? HEX_VALUES$2[code] : -1;
		if (digit < 0 || written === 16) throw new CodecError$2("BAD_UUID", path, "not a uuid: " + value);
		if (high < 0) {
			high = digit;
			continue;
		}
		out[written++] = high << 4 | digit;
		high = -1;
	}
	if (written !== 16 || high >= 0) throw new CodecError$2("BAD_UUID", path, "not a uuid: " + value);
	return out;
}
function bytesToUuid$2(bytes, path) {
	if (bytes.length !== 16) throw new CodecError$2("BAD_UUID", path, "uuid must be 16 bytes, got " + bytes.length);
	return HEX_PAIRS$2[bytes[0]] + HEX_PAIRS$2[bytes[1]] + HEX_PAIRS$2[bytes[2]] + HEX_PAIRS$2[bytes[3]] + "-" + HEX_PAIRS$2[bytes[4]] + HEX_PAIRS$2[bytes[5]] + "-" + HEX_PAIRS$2[bytes[6]] + HEX_PAIRS$2[bytes[7]] + "-" + HEX_PAIRS$2[bytes[8]] + HEX_PAIRS$2[bytes[9]] + "-" + HEX_PAIRS$2[bytes[10]] + HEX_PAIRS$2[bytes[11]] + HEX_PAIRS$2[bytes[12]] + HEX_PAIRS$2[bytes[13]] + HEX_PAIRS$2[bytes[14]] + HEX_PAIRS$2[bytes[15]];
}
var MS_PER_DAY$2 = 864e5;
var MIN_FOUR_DIGIT_MS$2 = -719528 * MS_PER_DAY$2;
var MAX_FOUR_DIGIT_MS$2 = 2932897 * MS_PER_DAY$2 - 1;
/** -1 unless both characters are digits. */
function twoDigits$2(value, index) {
	const high = value.charCodeAt(index) - 48;
	const low = value.charCodeAt(index + 1) - 48;
	if (high < 0 || high > 9 || low < 0 || low > 9) return -1;
	return high * 10 + low;
}
function daysInMonth$2(year, month) {
	if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
	if (month === 4 || month === 6 || month === 9 || month === 11) return 30;
	return 31;
}
/** Howard Hinnant's days_from_civil; exact for every proleptic Gregorian date. */
function daysFromCivil$2(year, month, day) {
	const shiftedYear = month <= 2 ? year - 1 : year;
	const era = Math.floor(shiftedYear / 400);
	const yearOfEra = shiftedYear - era * 400;
	const monthIndex = month > 2 ? month - 3 : month + 9;
	const dayOfYear = Math.floor((153 * monthIndex + 2) / 5) + day - 1;
	const dayOfEra = yearOfEra * 365 + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100) + dayOfYear;
	return era * 146097 + dayOfEra - 719468;
}
/** The inverse, packed as year * 10000 + month * 100 + day to avoid an allocation. */
function civilFromDays$2(days) {
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
function parseIsoDate$2(value) {
	const yearHigh = twoDigits$2(value, 0);
	const yearLow = twoDigits$2(value, 2);
	const month = twoDigits$2(value, 5);
	const day = twoDigits$2(value, 8);
	if (yearHigh < 0 || yearLow < 0 || month < 0 || day < 0) return NaN;
	if (value.charCodeAt(4) !== 45 || value.charCodeAt(7) !== 45) return NaN;
	const year = yearHigh * 100 + yearLow;
	if (month < 1 || month > 12 || day < 1 || day > daysInMonth$2(year, month)) return NaN;
	return daysFromCivil$2(year, month, day);
}
/** "00".."99", so zero-padding is a lookup instead of a padStart call. */
var TWO_DIGIT_STRINGS$2 = (() => {
	const strings = new Array(100);
	for (let value = 0; value < 100; value++) strings[value] = String(Math.floor(value / 10)) + String(value % 10);
	return strings;
})();
function formatIsoDate$2(packed) {
	const year = Math.floor(packed / 1e4);
	const month = Math.floor(packed / 100) % 100;
	const day = packed % 100;
	return TWO_DIGIT_STRINGS$2[Math.floor(year / 100)] + TWO_DIGIT_STRINGS$2[year % 100] + "-" + TWO_DIGIT_STRINGS$2[month] + "-" + TWO_DIGIT_STRINGS$2[day];
}
var lastFormattedDays$2 = NaN;
var lastFormattedDate$2 = "";
function formatDateFromDays$2(days) {
	if (days === lastFormattedDays$2) return lastFormattedDate$2;
	const formatted = formatIsoDate$2(civilFromDays$2(days));
	lastFormattedDays$2 = days;
	lastFormattedDate$2 = formatted;
	return formatted;
}
/** Epoch ms for the exact toISOString shape YYYY-MM-DDTHH:MM:SS.sssZ, else NaN. */
function parseIsoUtcTimestamp$2(value) {
	if (value.length !== 24) return NaN;
	if (value.charCodeAt(10) !== 84 || value.charCodeAt(13) !== 58 || value.charCodeAt(16) !== 58 || value.charCodeAt(19) !== 46 || value.charCodeAt(23) !== 90) return NaN;
	const days = parseIsoDate$2(value);
	const hours = twoDigits$2(value, 11);
	const minutes = twoDigits$2(value, 14);
	const seconds = twoDigits$2(value, 17);
	const millisHigh = twoDigits$2(value, 20);
	const millisLow = value.charCodeAt(22) - 48;
	if (Number.isNaN(days) || hours < 0 || minutes < 0 || seconds < 0 || millisHigh < 0) return NaN;
	if (millisLow < 0 || millisLow > 9) return NaN;
	if (hours > 23 || minutes > 59 || seconds > 59) return NaN;
	const secondOfDay = hours * 3600 + minutes * 60 + seconds;
	return days * MS_PER_DAY$2 + secondOfDay * 1e3 + millisHigh * 10 + millisLow;
}
function timestampToMillis$2(value, path) {
	const fast = parseIsoUtcTimestamp$2(value);
	if (!Number.isNaN(fast)) return fast;
	const ms = Date.parse(value);
	if (Number.isNaN(ms)) throw new CodecError$2("BAD_TIMESTAMP", path, "invalid timestamp " + value);
	return ms;
}
function millisToTimestamp$2(ms, path) {
	if (Number.isInteger(ms) && ms >= MIN_FOUR_DIGIT_MS$2 && ms <= MAX_FOUR_DIGIT_MS$2) return formatIsoUtcTimestamp$2(ms);
	const date = new Date(ms);
	if (Number.isNaN(date.getTime())) throw new CodecError$2("BAD_TIMESTAMP", path, "timestamp out of range");
	return date.toISOString();
}
function formatIsoUtcTimestamp$2(ms) {
	const days = Math.floor(ms / MS_PER_DAY$2);
	const msOfDay = ms - days * MS_PER_DAY$2;
	const secondOfDay = Math.floor(msOfDay / 1e3);
	const millis = msOfDay - secondOfDay * 1e3;
	const hours = Math.floor(secondOfDay / 3600);
	const minutes = Math.floor(secondOfDay % 3600 / 60);
	const seconds = secondOfDay % 60;
	return formatDateFromDays$2(days) + "T" + TWO_DIGIT_STRINGS$2[hours] + ":" + TWO_DIGIT_STRINGS$2[minutes] + ":" + TWO_DIGIT_STRINGS$2[seconds] + "." + TWO_DIGIT_STRINGS$2[Math.floor(millis / 10)] + String(millis % 10) + "Z";
}
/**
* Sort captured unknown fields by tag so they can be interleaved into the known
* fields' ascending order. Array.prototype.sort is stable, so several entries
* sharing a tag keep their original relative order.
*/
function prepareUnknown$2(unknown, known, path) {
	if (unknown === void 0 || unknown.length === 0) return [];
	for (const field of unknown) if (known.has(field.tag)) throw new CodecError$2("UNKNOWN_COLLISION", path, "unknown field carries tag " + field.tag + ", which this message declares");
	return [...unknown].sort((a, b) => a.tag - b.tag);
}
/** Emit every pending unknown field whose tag precedes the given tag. */
function flushUnknownBefore$2(writer, unknown, index, tag) {
	let cursor = index;
	while (cursor < unknown.length && unknown[cursor].tag < tag) {
		writer.raw(unknown[cursor].raw);
		cursor++;
	}
	return cursor;
}
function flushUnknownRest$2(writer, unknown, index) {
	for (let cursor = index; cursor < unknown.length; cursor++) writer.raw(unknown[cursor].raw);
}
/**
* Capture a field the schema does not declare. Retired tags are dropped instead:
* they are known-dead, so preserving them would grow every row forever.
*/
function captureUnknown$2(reader, key, tag, wire, into, retired) {
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
function missingField$2(path, name, tag) {
	return new CodecError$2("MISSING_FIELD", path, "required field '" + name + "' (tag " + tag + ") is absent");
}
function expectWire$2(actual, expected, path) {
	if (actual === expected) return;
	throw new CodecError$2("WIRE_MISMATCH", path, "expected wire type " + expected + ", got " + actual);
}
function readSignedField$2(reader, wire, path) {
	expectWire$2(wire, 0, path);
	return reader.varintSigned(path);
}
function readUnsignedField$2(reader, wire, path) {
	expectWire$2(wire, 0, path);
	return reader.varintUnsigned(path);
}
/**
* f32 and f64 both encode as I64, so this normally reads a double. I32 is
* accepted so payloads written before that rule stay readable.
*/
function readDoubleField$1(reader, wire, path) {
	if (wire === 5) return reader.float32();
	expectWire$2(wire, 1, path);
	return reader.double();
}
function readStringField$2(reader, wire, path) {
	expectWire$2(wire, 2, path);
	return reader.string();
}
function readBytesField$2(reader, wire, path) {
	expectWire$2(wire, 2, path);
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
	const unknown = prepareUnknown$2(value.$unknown, KNOWN_Name, path);
	let pending = 0;
	pending = flushUnknownBefore$2(w, unknown, pending, 1);
	if (value.family !== null && value.family !== void 0) {
		const present = value.family;
		w.key(1, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 2);
	if (value.given !== null && value.given !== void 0) {
		const present = value.given;
		w.key(2, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 3);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 4);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 5);
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
	flushUnknownRest$2(w, unknown, pending);
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
				field1 = readStringField$2(r, wire, path + ".family");
				break;
			case 2:
				field2 = readStringField$2(r, wire, path + ".given");
				break;
			case 3: {
				expectWire$2(wire, 2, path + ".additional");
				const wrapper = r.subMessage(path + ".additional");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$2(wrapper, innerWire, path + ".additional"));
				}
				field3 = items;
				break;
			}
			case 4: {
				expectWire$2(wire, 2, path + ".prefixes");
				const wrapper = r.subMessage(path + ".prefixes");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$2(wrapper, innerWire, path + ".prefixes"));
				}
				field4 = items;
				break;
			}
			case 5: {
				expectWire$2(wire, 2, path + ".suffixes");
				const wrapper = r.subMessage(path + ".suffixes");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$2(wrapper, innerWire, path + ".suffixes"));
				}
				field5 = items;
				break;
			}
			default: unknown = captureUnknown$2(r, wireKey, tag, wire, unknown, RETIRED_Name);
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
	const unknown = prepareUnknown$2(value.$unknown, KNOWN_Gender, path);
	let pending = 0;
	pending = flushUnknownBefore$2(w, unknown, pending, 1);
	if (value.sex !== null && value.sex !== void 0) {
		const present = value.sex;
		w.key(1, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 2);
	if (value.identity !== null && value.identity !== void 0) {
		const present = value.identity;
		w.key(2, 2);
		w.string(present);
	}
	flushUnknownRest$2(w, unknown, pending);
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
				field1 = readStringField$2(r, wire, path + ".sex");
				break;
			case 2:
				field2 = readStringField$2(r, wire, path + ".identity");
				break;
			default: unknown = captureUnknown$2(r, wireKey, tag, wire, unknown, RETIRED_Gender);
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
	const unknown = prepareUnknown$2(value.$unknown, KNOWN_Geo, path);
	let pending = 0;
	pending = flushUnknownBefore$2(w, unknown, pending, 1);
	w.key(1, 1);
	w.double(requireFinite$1(value.lat, path + ".lat"));
	pending = flushUnknownBefore$2(w, unknown, pending, 2);
	w.key(2, 1);
	w.double(requireFinite$1(value.lng, path + ".lng"));
	flushUnknownRest$2(w, unknown, pending);
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
				field1 = readDoubleField$1(r, wire, path + ".lat");
				break;
			case 2:
				field2 = readDoubleField$1(r, wire, path + ".lng");
				break;
			default: unknown = captureUnknown$2(r, wireKey, tag, wire, unknown, RETIRED_Geo);
		}
	}
	if (field1 === void 0) throw missingField$2(path, "lat", 1);
	if (field2 === void 0) throw missingField$2(path, "lng", 2);
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
	const unknown = prepareUnknown$2(value.$unknown, KNOWN_ContactField, path);
	let pending = 0;
	pending = flushUnknownBefore$2(w, unknown, pending, 1);
	w.key(1, 2);
	w.string(value.value);
	pending = flushUnknownBefore$2(w, unknown, pending, 2);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 3);
	if (value.pref !== null && value.pref !== void 0) {
		const present = value.pref;
		w.key(3, 0);
		w.varintNumber(requireInteger$2(present, path + ".pref"));
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 4);
	if (value.label !== null && value.label !== void 0) {
		const present = value.label;
		w.key(4, 2);
		w.string(present);
	}
	flushUnknownRest$2(w, unknown, pending);
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
				field1 = readStringField$2(r, wire, path + ".value");
				break;
			case 2: {
				expectWire$2(wire, 2, path + ".types");
				const wrapper = r.subMessage(path + ".types");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$2(wrapper, innerWire, path + ".types"));
				}
				field2 = items;
				break;
			}
			case 3:
				field3 = readSignedField$2(r, wire, path + ".pref");
				break;
			case 4:
				field4 = readStringField$2(r, wire, path + ".label");
				break;
			default: unknown = captureUnknown$2(r, wireKey, tag, wire, unknown, RETIRED_ContactField);
		}
	}
	if (field1 === void 0) throw missingField$2(path, "value", 1);
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
	const unknown = prepareUnknown$2(value.$unknown, KNOWN_Address, path);
	let pending = 0;
	pending = flushUnknownBefore$2(w, unknown, pending, 1);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 2);
	if (value.pref !== null && value.pref !== void 0) {
		const present = value.pref;
		w.key(2, 0);
		w.varintNumber(requireInteger$2(present, path + ".pref"));
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 3);
	if (value.label !== null && value.label !== void 0) {
		const present = value.label;
		w.key(3, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 4);
	if (value.po_box !== null && value.po_box !== void 0) {
		const present = value.po_box;
		w.key(4, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 5);
	if (value.ext !== null && value.ext !== void 0) {
		const present = value.ext;
		w.key(5, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 6);
	if (value.street !== null && value.street !== void 0) {
		const present = value.street;
		w.key(6, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 7);
	if (value.locality !== null && value.locality !== void 0) {
		const present = value.locality;
		w.key(7, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 8);
	if (value.region !== null && value.region !== void 0) {
		const present = value.region;
		w.key(8, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 9);
	if (value.postal_code !== null && value.postal_code !== void 0) {
		const present = value.postal_code;
		w.key(9, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 10);
	if (value.country !== null && value.country !== void 0) {
		const present = value.country;
		w.key(10, 2);
		w.string(present);
	}
	flushUnknownRest$2(w, unknown, pending);
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
				expectWire$2(wire, 2, path + ".types");
				const wrapper = r.subMessage(path + ".types");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$2(wrapper, innerWire, path + ".types"));
				}
				field1 = items;
				break;
			}
			case 2:
				field2 = readSignedField$2(r, wire, path + ".pref");
				break;
			case 3:
				field3 = readStringField$2(r, wire, path + ".label");
				break;
			case 4:
				field4 = readStringField$2(r, wire, path + ".po_box");
				break;
			case 5:
				field5 = readStringField$2(r, wire, path + ".ext");
				break;
			case 6:
				field6 = readStringField$2(r, wire, path + ".street");
				break;
			case 7:
				field7 = readStringField$2(r, wire, path + ".locality");
				break;
			case 8:
				field8 = readStringField$2(r, wire, path + ".region");
				break;
			case 9:
				field9 = readStringField$2(r, wire, path + ".postal_code");
				break;
			case 10:
				field10 = readStringField$2(r, wire, path + ".country");
				break;
			default: unknown = captureUnknown$2(r, wireKey, tag, wire, unknown, RETIRED_Address);
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
	const unknown = prepareUnknown$2(value.$unknown, KNOWN_ContactOrganization, path);
	let pending = 0;
	pending = flushUnknownBefore$2(w, unknown, pending, 1);
	w.key(1, 2);
	w.string(value.name);
	pending = flushUnknownBefore$2(w, unknown, pending, 2);
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
	flushUnknownRest$2(w, unknown, pending);
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
				field1 = readStringField$2(r, wire, path + ".name");
				break;
			case 2: {
				expectWire$2(wire, 2, path + ".units");
				const wrapper = r.subMessage(path + ".units");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$2(wrapper, innerWire, path + ".units"));
				}
				field2 = items;
				break;
			}
			default: unknown = captureUnknown$2(r, wireKey, tag, wire, unknown, RETIRED_ContactOrganization);
		}
	}
	if (field1 === void 0) throw missingField$2(path, "name", 1);
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
	const unknown = prepareUnknown$2(value.$unknown, KNOWN_CustomField, path);
	let pending = 0;
	pending = flushUnknownBefore$2(w, unknown, pending, 1);
	w.key(1, 2);
	w.string(value.label);
	pending = flushUnknownBefore$2(w, unknown, pending, 2);
	w.key(2, 2);
	w.string(value.value);
	flushUnknownRest$2(w, unknown, pending);
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
				field1 = readStringField$2(r, wire, path + ".label");
				break;
			case 2:
				field2 = readStringField$2(r, wire, path + ".value");
				break;
			default: unknown = captureUnknown$2(r, wireKey, tag, wire, unknown, RETIRED_CustomField);
		}
	}
	if (field1 === void 0) throw missingField$2(path, "label", 1);
	if (field2 === void 0) throw missingField$2(path, "value", 2);
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
	const unknown = prepareUnknown$2(value.$unknown, KNOWN_ContactRelation, path);
	let pending = 0;
	pending = flushUnknownBefore$2(w, unknown, pending, 1);
	w.key(1, 2);
	w.lengthDelimited(uuidToBytes$2(value.contact_id, path + ".contact_id"));
	pending = flushUnknownBefore$2(w, unknown, pending, 2);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 3);
	if (value.pref !== null && value.pref !== void 0) {
		const present = value.pref;
		w.key(3, 0);
		w.varintNumber(requireInteger$2(present, path + ".pref"));
	}
	flushUnknownRest$2(w, unknown, pending);
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
				field1 = bytesToUuid$2(readBytesField$2(r, wire, path + ".contact_id"), path + ".contact_id");
				break;
			case 2: {
				expectWire$2(wire, 2, path + ".types");
				const wrapper = r.subMessage(path + ".types");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$2(wrapper, innerWire, path + ".types"));
				}
				field2 = items;
				break;
			}
			case 3:
				field3 = readSignedField$2(r, wire, path + ".pref");
				break;
			default: unknown = captureUnknown$2(r, wireKey, tag, wire, unknown, RETIRED_ContactRelation);
		}
	}
	if (field1 === void 0) throw missingField$2(path, "contact_id", 1);
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
	const writer = new Writer$2();
	writeContact(writer, value, "Contact");
	return writer.finish();
}
function writeContact(w, value, path) {
	const unknown = prepareUnknown$2(value.$unknown, KNOWN_Contact, path);
	let pending = 0;
	pending = flushUnknownBefore$2(w, unknown, pending, 1);
	w.key(1, 2);
	w.lengthDelimited(uuidToBytes$2(value.id, path + ".id"));
	pending = flushUnknownBefore$2(w, unknown, pending, 2);
	w.key(2, 2);
	w.string(value.uid);
	pending = flushUnknownBefore$2(w, unknown, pending, 3);
	w.key(3, 2);
	w.string(value.kind);
	pending = flushUnknownBefore$2(w, unknown, pending, 4);
	w.key(4, 2);
	w.string(value.formatted_name);
	pending = flushUnknownBefore$2(w, unknown, pending, 5);
	if (value.name !== null && value.name !== void 0) {
		const present = value.name;
		w.key(5, 2);
		{
			const nestedOffset = w.beginNested();
			writeName(w, present, path + ".name");
			w.endNested(nestedOffset);
		}
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 6);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 7);
	if (value.birthday !== null && value.birthday !== void 0) {
		const present = value.birthday;
		w.key(7, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 8);
	if (value.anniversary !== null && value.anniversary !== void 0) {
		const present = value.anniversary;
		w.key(8, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 9);
	if (value.gender !== null && value.gender !== void 0) {
		const present = value.gender;
		w.key(9, 2);
		{
			const nestedOffset = w.beginNested();
			writeGender(w, present, path + ".gender");
			w.endNested(nestedOffset);
		}
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 10);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 11);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 12);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 13);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 14);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 15);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 16);
	if (value.title !== null && value.title !== void 0) {
		const present = value.title;
		w.key(16, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 17);
	if (value.role !== null && value.role !== void 0) {
		const present = value.role;
		w.key(17, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 18);
	if (value.timezone !== null && value.timezone !== void 0) {
		const present = value.timezone;
		w.key(18, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 19);
	if (value.geo !== null && value.geo !== void 0) {
		const present = value.geo;
		w.key(19, 2);
		{
			const nestedOffset = w.beginNested();
			writeGeo(w, present, path + ".geo");
			w.endNested(nestedOffset);
		}
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 20);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 21);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 22);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 23);
	if (value.source !== null && value.source !== void 0) {
		const present = value.source;
		w.key(23, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 24);
	if (value.prodid !== null && value.prodid !== void 0) {
		const present = value.prodid;
		w.key(24, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 25);
	if (value.fburl !== null && value.fburl !== void 0) {
		const present = value.fburl;
		w.key(25, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 26);
	if (value.caluri !== null && value.caluri !== void 0) {
		const present = value.caluri;
		w.key(26, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 27);
	if (value.caladruri !== null && value.caladruri !== void 0) {
		const present = value.caladruri;
		w.key(27, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 28);
	if (value.photo !== null && value.photo !== void 0) {
		const present = value.photo;
		w.key(28, 2);
		w.lengthDelimited(uuidToBytes$2(present, path + ".photo"));
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 29);
	if (value.logo !== null && value.logo !== void 0) {
		const present = value.logo;
		w.key(29, 2);
		w.lengthDelimited(uuidToBytes$2(present, path + ".logo"));
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 30);
	if (value.sound !== null && value.sound !== void 0) {
		const present = value.sound;
		w.key(30, 2);
		w.lengthDelimited(uuidToBytes$2(present, path + ".sound"));
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 31);
	if (value.key !== null && value.key !== void 0) {
		const present = value.key;
		w.key(31, 2);
		w.lengthDelimited(uuidToBytes$2(present, path + ".key"));
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 32);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 33);
	w.key(33, 0);
	w.varintNumber(value.favorite ? 1 : 0);
	pending = flushUnknownBefore$2(w, unknown, pending, 34);
	w.key(34, 0);
	w.varintNumber(value.archived ? 1 : 0);
	pending = flushUnknownBefore$2(w, unknown, pending, 35);
	w.key(35, 0);
	w.varintNumber(value.deleted ? 1 : 0);
	pending = flushUnknownBefore$2(w, unknown, pending, 36);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 37);
	if (value.member_ids !== null && value.member_ids !== void 0) {
		const present = value.member_ids;
		w.key(37, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.lengthDelimited(uuidToBytes$2(item, path + ".member_ids"));
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 38);
	w.key(38, 0);
	w.varintNumber(timestampToMillis$2(value.created_at, path + ".created_at"));
	pending = flushUnknownBefore$2(w, unknown, pending, 39);
	w.key(39, 0);
	w.varintNumber(timestampToMillis$2(value.updated_at, path + ".updated_at"));
	flushUnknownRest$2(w, unknown, pending);
}
function decodeContact(bytes) {
	return readContact(Reader$2.of(bytes, "Contact"), "Contact");
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
				field1 = bytesToUuid$2(readBytesField$2(r, wire, path + ".id"), path + ".id");
				break;
			case 2:
				field2 = readStringField$2(r, wire, path + ".uid");
				break;
			case 3:
				field3 = readStringField$2(r, wire, path + ".kind");
				break;
			case 4:
				field4 = readStringField$2(r, wire, path + ".formatted_name");
				break;
			case 5:
				field5 = readName((expectWire$2(wire, 2, path + ".name"), r.subMessage(path + ".name")), path + ".name");
				break;
			case 6: {
				expectWire$2(wire, 2, path + ".nicknames");
				const wrapper = r.subMessage(path + ".nicknames");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$2(wrapper, innerWire, path + ".nicknames"));
				}
				field6 = items;
				break;
			}
			case 7:
				field7 = readStringField$2(r, wire, path + ".birthday");
				break;
			case 8:
				field8 = readStringField$2(r, wire, path + ".anniversary");
				break;
			case 9:
				field9 = readGender((expectWire$2(wire, 2, path + ".gender"), r.subMessage(path + ".gender")), path + ".gender");
				break;
			case 10: {
				expectWire$2(wire, 2, path + ".emails");
				const wrapper = r.subMessage(path + ".emails");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire$2(innerWire, 2, path + ".emails"), wrapper.subMessage(path + ".emails")), path + ".emails"));
				}
				field10 = items;
				break;
			}
			case 11: {
				expectWire$2(wire, 2, path + ".phones");
				const wrapper = r.subMessage(path + ".phones");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire$2(innerWire, 2, path + ".phones"), wrapper.subMessage(path + ".phones")), path + ".phones"));
				}
				field11 = items;
				break;
			}
			case 12: {
				expectWire$2(wire, 2, path + ".impps");
				const wrapper = r.subMessage(path + ".impps");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire$2(innerWire, 2, path + ".impps"), wrapper.subMessage(path + ".impps")), path + ".impps"));
				}
				field12 = items;
				break;
			}
			case 13: {
				expectWire$2(wire, 2, path + ".languages");
				const wrapper = r.subMessage(path + ".languages");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire$2(innerWire, 2, path + ".languages"), wrapper.subMessage(path + ".languages")), path + ".languages"));
				}
				field13 = items;
				break;
			}
			case 14: {
				expectWire$2(wire, 2, path + ".addresses");
				const wrapper = r.subMessage(path + ".addresses");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readAddress((expectWire$2(innerWire, 2, path + ".addresses"), wrapper.subMessage(path + ".addresses")), path + ".addresses"));
				}
				field14 = items;
				break;
			}
			case 15: {
				expectWire$2(wire, 2, path + ".organizations");
				const wrapper = r.subMessage(path + ".organizations");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactOrganization((expectWire$2(innerWire, 2, path + ".organizations"), wrapper.subMessage(path + ".organizations")), path + ".organizations"));
				}
				field15 = items;
				break;
			}
			case 16:
				field16 = readStringField$2(r, wire, path + ".title");
				break;
			case 17:
				field17 = readStringField$2(r, wire, path + ".role");
				break;
			case 18:
				field18 = readStringField$2(r, wire, path + ".timezone");
				break;
			case 19:
				field19 = readGeo((expectWire$2(wire, 2, path + ".geo"), r.subMessage(path + ".geo")), path + ".geo");
				break;
			case 20: {
				expectWire$2(wire, 2, path + ".categories");
				const wrapper = r.subMessage(path + ".categories");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$2(wrapper, innerWire, path + ".categories"));
				}
				field20 = items;
				break;
			}
			case 21: {
				expectWire$2(wire, 2, path + ".notes");
				const wrapper = r.subMessage(path + ".notes");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$2(wrapper, innerWire, path + ".notes"));
				}
				field21 = items;
				break;
			}
			case 22: {
				expectWire$2(wire, 2, path + ".urls");
				const wrapper = r.subMessage(path + ".urls");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire$2(innerWire, 2, path + ".urls"), wrapper.subMessage(path + ".urls")), path + ".urls"));
				}
				field22 = items;
				break;
			}
			case 23:
				field23 = readStringField$2(r, wire, path + ".source");
				break;
			case 24:
				field24 = readStringField$2(r, wire, path + ".prodid");
				break;
			case 25:
				field25 = readStringField$2(r, wire, path + ".fburl");
				break;
			case 26:
				field26 = readStringField$2(r, wire, path + ".caluri");
				break;
			case 27:
				field27 = readStringField$2(r, wire, path + ".caladruri");
				break;
			case 28:
				field28 = bytesToUuid$2(readBytesField$2(r, wire, path + ".photo"), path + ".photo");
				break;
			case 29:
				field29 = bytesToUuid$2(readBytesField$2(r, wire, path + ".logo"), path + ".logo");
				break;
			case 30:
				field30 = bytesToUuid$2(readBytesField$2(r, wire, path + ".sound"), path + ".sound");
				break;
			case 31:
				field31 = bytesToUuid$2(readBytesField$2(r, wire, path + ".key"), path + ".key");
				break;
			case 32: {
				expectWire$2(wire, 2, path + ".custom_fields");
				const wrapper = r.subMessage(path + ".custom_fields");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readCustomField((expectWire$2(innerWire, 2, path + ".custom_fields"), wrapper.subMessage(path + ".custom_fields")), path + ".custom_fields"));
				}
				field32 = items;
				break;
			}
			case 33:
				field33 = readUnsignedField$2(r, wire, path + ".favorite") !== 0;
				break;
			case 34:
				field34 = readUnsignedField$2(r, wire, path + ".archived") !== 0;
				break;
			case 35:
				field35 = readUnsignedField$2(r, wire, path + ".deleted") !== 0;
				break;
			case 36: {
				expectWire$2(wire, 2, path + ".related");
				const wrapper = r.subMessage(path + ".related");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactRelation((expectWire$2(innerWire, 2, path + ".related"), wrapper.subMessage(path + ".related")), path + ".related"));
				}
				field36 = items;
				break;
			}
			case 37: {
				expectWire$2(wire, 2, path + ".member_ids");
				const wrapper = r.subMessage(path + ".member_ids");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(bytesToUuid$2(readBytesField$2(wrapper, innerWire, path + ".member_ids"), path + ".member_ids"));
				}
				field37 = items;
				break;
			}
			case 38:
				field38 = millisToTimestamp$2(readSignedField$2(r, wire, path + ".created_at"), path + ".created_at");
				break;
			case 39:
				field39 = millisToTimestamp$2(readSignedField$2(r, wire, path + ".updated_at"), path + ".updated_at");
				break;
			default: unknown = captureUnknown$2(r, wireKey, tag, wire, unknown, RETIRED_Contact);
		}
	}
	if (field1 === void 0) throw missingField$2(path, "id", 1);
	if (field2 === void 0) throw missingField$2(path, "uid", 2);
	if (field3 === void 0) throw missingField$2(path, "kind", 3);
	if (field4 === void 0) throw missingField$2(path, "formatted_name", 4);
	if (field33 === void 0) throw missingField$2(path, "favorite", 33);
	if (field34 === void 0) throw missingField$2(path, "archived", 34);
	if (field35 === void 0) throw missingField$2(path, "deleted", 35);
	if (field38 === void 0) throw missingField$2(path, "created_at", 38);
	if (field39 === void 0) throw missingField$2(path, "updated_at", 39);
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
var KNOWN_ContactVersion = /* @__PURE__ */ new Set([
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
	39,
	40
]);
var RETIRED_ContactVersion = /* @__PURE__ */ new Set([]);
function encodeContactVersion(value) {
	const writer = new Writer$2();
	writeContactVersion(writer, value, "ContactVersion");
	return writer.finish();
}
function writeContactVersion(w, value, path) {
	const unknown = prepareUnknown$2(value.$unknown, KNOWN_ContactVersion, path);
	let pending = 0;
	pending = flushUnknownBefore$2(w, unknown, pending, 1);
	w.key(1, 2);
	w.lengthDelimited(uuidToBytes$2(value.id, path + ".id"));
	pending = flushUnknownBefore$2(w, unknown, pending, 2);
	w.key(2, 2);
	w.lengthDelimited(uuidToBytes$2(value.contact_id, path + ".contact_id"));
	pending = flushUnknownBefore$2(w, unknown, pending, 3);
	w.key(3, 2);
	w.string(value.uid);
	pending = flushUnknownBefore$2(w, unknown, pending, 4);
	w.key(4, 2);
	w.string(value.kind);
	pending = flushUnknownBefore$2(w, unknown, pending, 5);
	w.key(5, 2);
	w.string(value.formatted_name);
	pending = flushUnknownBefore$2(w, unknown, pending, 6);
	if (value.name !== null && value.name !== void 0) {
		const present = value.name;
		w.key(6, 2);
		{
			const nestedOffset = w.beginNested();
			writeName(w, present, path + ".name");
			w.endNested(nestedOffset);
		}
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 7);
	if (value.nicknames !== null && value.nicknames !== void 0) {
		const present = value.nicknames;
		w.key(7, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 8);
	if (value.birthday !== null && value.birthday !== void 0) {
		const present = value.birthday;
		w.key(8, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 9);
	if (value.anniversary !== null && value.anniversary !== void 0) {
		const present = value.anniversary;
		w.key(9, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 10);
	if (value.gender !== null && value.gender !== void 0) {
		const present = value.gender;
		w.key(10, 2);
		{
			const nestedOffset = w.beginNested();
			writeGender(w, present, path + ".gender");
			w.endNested(nestedOffset);
		}
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 11);
	if (value.emails !== null && value.emails !== void 0) {
		const present = value.emails;
		w.key(11, 2);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 12);
	if (value.phones !== null && value.phones !== void 0) {
		const present = value.phones;
		w.key(12, 2);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 13);
	if (value.impps !== null && value.impps !== void 0) {
		const present = value.impps;
		w.key(13, 2);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 14);
	if (value.languages !== null && value.languages !== void 0) {
		const present = value.languages;
		w.key(14, 2);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 15);
	if (value.addresses !== null && value.addresses !== void 0) {
		const present = value.addresses;
		w.key(15, 2);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 16);
	if (value.organizations !== null && value.organizations !== void 0) {
		const present = value.organizations;
		w.key(16, 2);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 17);
	if (value.title !== null && value.title !== void 0) {
		const present = value.title;
		w.key(17, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 18);
	if (value.role !== null && value.role !== void 0) {
		const present = value.role;
		w.key(18, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 19);
	if (value.timezone !== null && value.timezone !== void 0) {
		const present = value.timezone;
		w.key(19, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 20);
	if (value.geo !== null && value.geo !== void 0) {
		const present = value.geo;
		w.key(20, 2);
		{
			const nestedOffset = w.beginNested();
			writeGeo(w, present, path + ".geo");
			w.endNested(nestedOffset);
		}
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 21);
	if (value.categories !== null && value.categories !== void 0) {
		const present = value.categories;
		w.key(21, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 22);
	if (value.notes !== null && value.notes !== void 0) {
		const present = value.notes;
		w.key(22, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 23);
	if (value.urls !== null && value.urls !== void 0) {
		const present = value.urls;
		w.key(23, 2);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 24);
	if (value.source !== null && value.source !== void 0) {
		const present = value.source;
		w.key(24, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 25);
	if (value.prodid !== null && value.prodid !== void 0) {
		const present = value.prodid;
		w.key(25, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 26);
	if (value.fburl !== null && value.fburl !== void 0) {
		const present = value.fburl;
		w.key(26, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 27);
	if (value.caluri !== null && value.caluri !== void 0) {
		const present = value.caluri;
		w.key(27, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 28);
	if (value.caladruri !== null && value.caladruri !== void 0) {
		const present = value.caladruri;
		w.key(28, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 29);
	if (value.photo !== null && value.photo !== void 0) {
		const present = value.photo;
		w.key(29, 2);
		w.lengthDelimited(uuidToBytes$2(present, path + ".photo"));
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 30);
	if (value.logo !== null && value.logo !== void 0) {
		const present = value.logo;
		w.key(30, 2);
		w.lengthDelimited(uuidToBytes$2(present, path + ".logo"));
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 31);
	if (value.sound !== null && value.sound !== void 0) {
		const present = value.sound;
		w.key(31, 2);
		w.lengthDelimited(uuidToBytes$2(present, path + ".sound"));
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 32);
	if (value.key !== null && value.key !== void 0) {
		const present = value.key;
		w.key(32, 2);
		w.lengthDelimited(uuidToBytes$2(present, path + ".key"));
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 33);
	if (value.custom_fields !== null && value.custom_fields !== void 0) {
		const present = value.custom_fields;
		w.key(33, 2);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 34);
	w.key(34, 0);
	w.varintNumber(value.favorite ? 1 : 0);
	pending = flushUnknownBefore$2(w, unknown, pending, 35);
	w.key(35, 0);
	w.varintNumber(value.archived ? 1 : 0);
	pending = flushUnknownBefore$2(w, unknown, pending, 36);
	w.key(36, 0);
	w.varintNumber(value.deleted ? 1 : 0);
	pending = flushUnknownBefore$2(w, unknown, pending, 37);
	w.key(37, 0);
	w.varintNumber(timestampToMillis$2(value.created_at, path + ".created_at"));
	pending = flushUnknownBefore$2(w, unknown, pending, 38);
	if (value.parent_ids !== null && value.parent_ids !== void 0) {
		const present = value.parent_ids;
		w.key(38, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.lengthDelimited(uuidToBytes$2(item, path + ".parent_ids"));
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore$2(w, unknown, pending, 39);
	if (value.related !== null && value.related !== void 0) {
		const present = value.related;
		w.key(39, 2);
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
	pending = flushUnknownBefore$2(w, unknown, pending, 40);
	if (value.member_ids !== null && value.member_ids !== void 0) {
		const present = value.member_ids;
		w.key(40, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.lengthDelimited(uuidToBytes$2(item, path + ".member_ids"));
		}
		w.endNested(wrapperOffset);
	}
	flushUnknownRest$2(w, unknown, pending);
}
function decodeContactVersion(bytes) {
	return readContactVersion(Reader$2.of(bytes, "ContactVersion"), "ContactVersion");
}
function readContactVersion(r, path) {
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
	let field40;
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1:
				field1 = bytesToUuid$2(readBytesField$2(r, wire, path + ".id"), path + ".id");
				break;
			case 2:
				field2 = bytesToUuid$2(readBytesField$2(r, wire, path + ".contact_id"), path + ".contact_id");
				break;
			case 3:
				field3 = readStringField$2(r, wire, path + ".uid");
				break;
			case 4:
				field4 = readStringField$2(r, wire, path + ".kind");
				break;
			case 5:
				field5 = readStringField$2(r, wire, path + ".formatted_name");
				break;
			case 6:
				field6 = readName((expectWire$2(wire, 2, path + ".name"), r.subMessage(path + ".name")), path + ".name");
				break;
			case 7: {
				expectWire$2(wire, 2, path + ".nicknames");
				const wrapper = r.subMessage(path + ".nicknames");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$2(wrapper, innerWire, path + ".nicknames"));
				}
				field7 = items;
				break;
			}
			case 8:
				field8 = readStringField$2(r, wire, path + ".birthday");
				break;
			case 9:
				field9 = readStringField$2(r, wire, path + ".anniversary");
				break;
			case 10:
				field10 = readGender((expectWire$2(wire, 2, path + ".gender"), r.subMessage(path + ".gender")), path + ".gender");
				break;
			case 11: {
				expectWire$2(wire, 2, path + ".emails");
				const wrapper = r.subMessage(path + ".emails");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire$2(innerWire, 2, path + ".emails"), wrapper.subMessage(path + ".emails")), path + ".emails"));
				}
				field11 = items;
				break;
			}
			case 12: {
				expectWire$2(wire, 2, path + ".phones");
				const wrapper = r.subMessage(path + ".phones");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire$2(innerWire, 2, path + ".phones"), wrapper.subMessage(path + ".phones")), path + ".phones"));
				}
				field12 = items;
				break;
			}
			case 13: {
				expectWire$2(wire, 2, path + ".impps");
				const wrapper = r.subMessage(path + ".impps");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire$2(innerWire, 2, path + ".impps"), wrapper.subMessage(path + ".impps")), path + ".impps"));
				}
				field13 = items;
				break;
			}
			case 14: {
				expectWire$2(wire, 2, path + ".languages");
				const wrapper = r.subMessage(path + ".languages");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire$2(innerWire, 2, path + ".languages"), wrapper.subMessage(path + ".languages")), path + ".languages"));
				}
				field14 = items;
				break;
			}
			case 15: {
				expectWire$2(wire, 2, path + ".addresses");
				const wrapper = r.subMessage(path + ".addresses");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readAddress((expectWire$2(innerWire, 2, path + ".addresses"), wrapper.subMessage(path + ".addresses")), path + ".addresses"));
				}
				field15 = items;
				break;
			}
			case 16: {
				expectWire$2(wire, 2, path + ".organizations");
				const wrapper = r.subMessage(path + ".organizations");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactOrganization((expectWire$2(innerWire, 2, path + ".organizations"), wrapper.subMessage(path + ".organizations")), path + ".organizations"));
				}
				field16 = items;
				break;
			}
			case 17:
				field17 = readStringField$2(r, wire, path + ".title");
				break;
			case 18:
				field18 = readStringField$2(r, wire, path + ".role");
				break;
			case 19:
				field19 = readStringField$2(r, wire, path + ".timezone");
				break;
			case 20:
				field20 = readGeo((expectWire$2(wire, 2, path + ".geo"), r.subMessage(path + ".geo")), path + ".geo");
				break;
			case 21: {
				expectWire$2(wire, 2, path + ".categories");
				const wrapper = r.subMessage(path + ".categories");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$2(wrapper, innerWire, path + ".categories"));
				}
				field21 = items;
				break;
			}
			case 22: {
				expectWire$2(wire, 2, path + ".notes");
				const wrapper = r.subMessage(path + ".notes");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$2(wrapper, innerWire, path + ".notes"));
				}
				field22 = items;
				break;
			}
			case 23: {
				expectWire$2(wire, 2, path + ".urls");
				const wrapper = r.subMessage(path + ".urls");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactField((expectWire$2(innerWire, 2, path + ".urls"), wrapper.subMessage(path + ".urls")), path + ".urls"));
				}
				field23 = items;
				break;
			}
			case 24:
				field24 = readStringField$2(r, wire, path + ".source");
				break;
			case 25:
				field25 = readStringField$2(r, wire, path + ".prodid");
				break;
			case 26:
				field26 = readStringField$2(r, wire, path + ".fburl");
				break;
			case 27:
				field27 = readStringField$2(r, wire, path + ".caluri");
				break;
			case 28:
				field28 = readStringField$2(r, wire, path + ".caladruri");
				break;
			case 29:
				field29 = bytesToUuid$2(readBytesField$2(r, wire, path + ".photo"), path + ".photo");
				break;
			case 30:
				field30 = bytesToUuid$2(readBytesField$2(r, wire, path + ".logo"), path + ".logo");
				break;
			case 31:
				field31 = bytesToUuid$2(readBytesField$2(r, wire, path + ".sound"), path + ".sound");
				break;
			case 32:
				field32 = bytesToUuid$2(readBytesField$2(r, wire, path + ".key"), path + ".key");
				break;
			case 33: {
				expectWire$2(wire, 2, path + ".custom_fields");
				const wrapper = r.subMessage(path + ".custom_fields");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readCustomField((expectWire$2(innerWire, 2, path + ".custom_fields"), wrapper.subMessage(path + ".custom_fields")), path + ".custom_fields"));
				}
				field33 = items;
				break;
			}
			case 34:
				field34 = readUnsignedField$2(r, wire, path + ".favorite") !== 0;
				break;
			case 35:
				field35 = readUnsignedField$2(r, wire, path + ".archived") !== 0;
				break;
			case 36:
				field36 = readUnsignedField$2(r, wire, path + ".deleted") !== 0;
				break;
			case 37:
				field37 = millisToTimestamp$2(readSignedField$2(r, wire, path + ".created_at"), path + ".created_at");
				break;
			case 38: {
				expectWire$2(wire, 2, path + ".parent_ids");
				const wrapper = r.subMessage(path + ".parent_ids");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(bytesToUuid$2(readBytesField$2(wrapper, innerWire, path + ".parent_ids"), path + ".parent_ids"));
				}
				field38 = items;
				break;
			}
			case 39: {
				expectWire$2(wire, 2, path + ".related");
				const wrapper = r.subMessage(path + ".related");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readContactRelation((expectWire$2(innerWire, 2, path + ".related"), wrapper.subMessage(path + ".related")), path + ".related"));
				}
				field39 = items;
				break;
			}
			case 40: {
				expectWire$2(wire, 2, path + ".member_ids");
				const wrapper = r.subMessage(path + ".member_ids");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(bytesToUuid$2(readBytesField$2(wrapper, innerWire, path + ".member_ids"), path + ".member_ids"));
				}
				field40 = items;
				break;
			}
			default: unknown = captureUnknown$2(r, wireKey, tag, wire, unknown, RETIRED_ContactVersion);
		}
	}
	if (field1 === void 0) throw missingField$2(path, "id", 1);
	if (field2 === void 0) throw missingField$2(path, "contact_id", 2);
	if (field3 === void 0) throw missingField$2(path, "uid", 3);
	if (field4 === void 0) throw missingField$2(path, "kind", 4);
	if (field5 === void 0) throw missingField$2(path, "formatted_name", 5);
	if (field34 === void 0) throw missingField$2(path, "favorite", 34);
	if (field35 === void 0) throw missingField$2(path, "archived", 35);
	if (field36 === void 0) throw missingField$2(path, "deleted", 36);
	if (field37 === void 0) throw missingField$2(path, "created_at", 37);
	const result = {
		id: field1,
		contact_id: field2,
		uid: field3,
		kind: field4,
		formatted_name: field5,
		name: field6,
		nicknames: field7,
		birthday: field8,
		anniversary: field9,
		gender: field10,
		emails: field11,
		phones: field12,
		impps: field13,
		languages: field14,
		addresses: field15,
		organizations: field16,
		title: field17,
		role: field18,
		timezone: field19,
		geo: field20,
		categories: field21,
		notes: field22,
		urls: field23,
		source: field24,
		prodid: field25,
		fburl: field26,
		caluri: field27,
		caladruri: field28,
		photo: field29,
		logo: field30,
		sound: field31,
		key: field32,
		custom_fields: field33,
		favorite: field34,
		archived: field35,
		deleted: field36,
		created_at: field37,
		parent_ids: field38,
		related: field39,
		member_ids: field40
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
//#endregion
//#region src/vault/merge.ts
function lastWriterWins(local, remote) {
	if (local.updatedAt > remote.updatedAt) return local.data;
	if (local.updatedAt < remote.updatedAt) return remote.data;
	if (local.authorId > remote.authorId) return local.data;
	if (local.authorId < remote.authorId) return remote.data;
	if (local.seq > remote.seq) return local.data;
	return remote.data;
}
//#endregion
//#region src/vault/collections/contacts.ts
/** vCard UID for a new contact; 32 hex chars, minted here so apps never do. */
function mintUid$2() {
	return crypto.randomUUID().replace(/-/g, "");
}
var contactsCollection = {
	name: "contacts",
	encodeRow: encodeContact,
	decodeRow: decodeContact,
	encodeVersion: encodeContactVersion,
	decodeVersion: decodeContactVersion,
	prepare(input, existing, id, now) {
		return {
			kind: "individual",
			formatted_name: "",
			favorite: false,
			archived: false,
			deleted: false,
			...input,
			id,
			uid: input.uid || existing?.uid || mintUid$2(),
			created_at: input.created_at || existing?.created_at || now,
			updated_at: now
		};
	},
	versionOf(versionId, row, parentIds, createdAt) {
		const { id, related, member_ids, created_at, updated_at, $unknown, ...rest } = row;
		return {
			...rest,
			id: versionId,
			contact_id: id,
			related,
			member_ids,
			created_at: createdAt,
			parent_ids: parentIds.length > 0 ? parentIds : void 0
		};
	},
	rowFieldsOf(version) {
		const { id, contact_id, created_at, parent_ids, $unknown, ...rest } = version;
		return rest;
	},
	merge: lastWriterWins,
	fields: {
		formatted_name: {
			kind: "string",
			get: (row) => row.formatted_name
		},
		kind: {
			kind: "string",
			get: (row) => row.kind
		},
		birthday: {
			kind: "string",
			get: (row) => row.birthday
		},
		anniversary: {
			kind: "string",
			get: (row) => row.anniversary
		},
		title: {
			kind: "string",
			get: (row) => row.title
		},
		role: {
			kind: "string",
			get: (row) => row.role
		},
		timezone: {
			kind: "string",
			get: (row) => row.timezone
		},
		favorite: {
			kind: "bool",
			get: (row) => row.favorite
		},
		archived: {
			kind: "bool",
			get: (row) => row.archived
		},
		deleted: {
			kind: "bool",
			get: (row) => row.deleted
		},
		categories: {
			kind: "stringList",
			get: (row) => row.categories
		},
		nicknames: {
			kind: "stringList",
			get: (row) => row.nicknames
		},
		notes: {
			kind: "stringList",
			get: (row) => row.notes
		},
		emails: {
			kind: "fieldList",
			get: (row) => row.emails
		},
		phones: {
			kind: "fieldList",
			get: (row) => row.phones
		},
		impps: {
			kind: "fieldList",
			get: (row) => row.impps
		},
		languages: {
			kind: "fieldList",
			get: (row) => row.languages
		},
		urls: {
			kind: "fieldList",
			get: (row) => row.urls
		},
		created_at: {
			kind: "date",
			get: (row) => row.created_at
		},
		updated_at: {
			kind: "date",
			get: (row) => row.updated_at
		},
		geo: {
			kind: "geo",
			get: (row) => row.geo
		}
	},
	searchText: (row) => [
		row.formatted_name,
		...list(row.emails).map((field) => field.value),
		...list(row.phones).map((field) => field.value)
	],
	matchesScope(row, scope) {
		if (scope === "ALL") return true;
		if (scope === "TRASHED") return row.deleted;
		if (row.deleted) return false;
		if (scope === "ARCHIVED") return row.archived;
		return !row.archived;
	},
	comparators: {
		FORMATTED_NAME: (a, b) => compareText(a.formatted_name, b.formatted_name),
		CREATED_AT: (a, b) => compareDates(a.created_at, b.created_at),
		UPDATED_AT: (a, b) => compareDates(a.updated_at, b.updated_at),
		BIRTHDAY: (a, b) => compareText(a.birthday, b.birthday)
	},
	defaultSort: [{
		field: "FORMATTED_NAME",
		direction: "ASC"
	}],
	matchesExtras(row, options) {
		if (options.favorite === void 0) return true;
		return row.favorite === options.favorite;
	}
};
/** Guards against a hostile buffer driving unbounded recursion. */
var MAX_DEPTH$1 = 100;
/** Above this a double can no longer represent every integer exactly. */
var MAX_SAFE$1 = 9007199254740991;
var TWO_TO_32$1 = 4294967296;
var CodecError$1 = class extends Error {
	constructor(code, path, message) {
		super(path.length > 0 ? path + ": " + message : message);
		this.code = code;
		this.path = path;
		this.name = "CodecError";
	}
};
var textEncoder$1 = new TextEncoder();
var textDecoder$1 = new TextDecoder("utf-8", { fatal: true });
function isSurrogatePair$1(value, index) {
	if ((value.charCodeAt(index) & 64512) !== 55296) return false;
	return (value.charCodeAt(index + 1) & 64512) === 56320;
}
function utf8Length$1(value) {
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
		if (isSurrogatePair$1(value, index)) {
			length += 4;
			index++;
			continue;
		}
		length += 3;
	}
	return length;
}
/** The caller has already reserved utf8Length(value) bytes at offset. */
function writeUtf8$1(bytes, offset, value) {
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
		if (isSurrogatePair$1(value, index)) {
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
function varintWidth$1(value) {
	if (value < 128) return 1;
	if (value < 16384) return 2;
	if (value < 2097152) return 3;
	if (value < 268435456) return 4;
	return 5;
}
function writeVarintAt$1(bytes, offset, value) {
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
var pooledBuffer$1 = null;
/** Rows larger than this are rare enough that retaining the buffer is waste. */
var MAX_POOLED_CAPACITY$1 = 65536;
var Writer$1 = class {
	constructor(capacity = 256) {
		this.view = null;
		this.length = 0;
		if (pooledBuffer$1 !== null && pooledBuffer$1.length >= capacity) {
			this.bytes = pooledBuffer$1;
			pooledBuffer$1 = null;
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
		const byteLength = utf8Length$1(value);
		this.varintNumber(byteLength);
		this.reserve(byteLength);
		writeUtf8$1(this.bytes, this.length, value);
		this.length += byteLength;
	}
	longString(value) {
		const lengthOffset = this.beginLengthDelimited();
		this.reserve(value.length * 3);
		const written = textEncoder$1.encodeInto(value, this.bytes.subarray(this.length)).written;
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
		const width = varintWidth$1(bodyLength);
		if (width > 1) {
			this.reserve(width - 1);
			this.bytes.copyWithin(bodyStart + width - 1, bodyStart, this.length);
			this.length += width - 1;
		}
		writeVarintAt$1(this.bytes, lengthOffset, bodyLength);
	}
	finish() {
		const result = this.bytes.slice(0, this.length);
		if (this.bytes.length <= MAX_POOLED_CAPACITY$1 && (pooledBuffer$1 === null || pooledBuffer$1.length < this.bytes.length)) pooledBuffer$1 = this.bytes;
		return result;
	}
};
/** Shared float conversion area \u2014 cheaper than a DataView per read. */
var scratchBytes$1 = /* @__PURE__ */ new Uint8Array(8);
var scratchView$1 = new DataView(scratchBytes$1.buffer);
function copyToScratch$1(buffer, position, count) {
	for (let index = 0; index < count; index++) scratchBytes$1[index] = buffer[position + index];
}
/**
* null when any byte is non-ASCII; the caller falls back to TextDecoder.
* Rope concatenation measures faster here than fromCharCode.apply and than
* TextDecoder itself for the short fields that dominate real rows.
*/
function asciiString$1(buffer, start, length) {
	const end = start + length;
	for (let index = start; index < end; index++) if (buffer[index] > 127) return null;
	let out = "";
	for (let index = start; index < end; index++) out += String.fromCharCode(buffer[index]);
	return out;
}
var Reader$1 = class Reader$1 {
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
		return new Reader$1(bytes, 0, bytes.length, 0, path);
	}
	hasMore() {
		return this.position < this.end;
	}
	require(count) {
		if (this.position + count > this.end) throw new CodecError$1("TRUNCATED", this.path, "buffer ended mid-value");
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
		throw new CodecError$1("OVERLONG_VARINT", this.path, "varint exceeds 10 bytes");
	}
	commitVarint(position, lo, hi) {
		this.position = position;
		this.lo = lo >>> 0;
		this.hi = hi >>> 0;
	}
	truncated() {
		return new CodecError$1("TRUNCATED", this.path, "buffer ended mid-value");
	}
	/** The raw 64-bit value, unsigned. Only for i64/u64/duration. */
	varint() {
		this.readVarint64();
		if (this.hi === 0) return BigInt(this.lo);
		return BigInt(this.hi) << 32n | BigInt(this.lo);
	}
	varintUnsigned(path) {
		this.readVarint64();
		return unsignedFromHalves$1(this.lo, this.hi, path);
	}
	varintSigned(path) {
		this.readVarint64();
		return signedFromHalves$1(this.lo, this.hi, path);
	}
	skipVarint() {
		this.readVarint64();
	}
	key() {
		this.readVarint64();
		if (this.hi !== 0) throw new CodecError$1("BAD_TAG", this.path, "wire key exceeds 32 bits");
		return this.lo;
	}
	/** A length prefix: non-negative and inside the remaining buffer. */
	length() {
		this.readVarint64();
		const value = unsignedFromHalves$1(this.lo, this.hi, this.path);
		if (this.position + value > this.end) throw new CodecError$1("TRUNCATED", this.path, "length-delimited field runs past the buffer");
		return value;
	}
	double() {
		this.require(8);
		copyToScratch$1(this.buffer, this.position, 8);
		this.position += 8;
		return scratchView$1.getFloat64(0, true);
	}
	float32() {
		this.require(4);
		copyToScratch$1(this.buffer, this.position, 4);
		this.position += 4;
		return scratchView$1.getFloat32(0, true);
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
		if (this.depth + 1 > MAX_DEPTH$1) throw new CodecError$1("DEPTH", path, "message nesting exceeds 100");
		const length = this.length();
		const start = this.position;
		this.position += length;
		return new Reader$1(this.buffer, start, start + length, this.depth + 1, path);
	}
	/** A bounded Reader over a packed repeated body. */
	packed(path) {
		const length = this.length();
		const start = this.position;
		this.position += length;
		return new Reader$1(this.buffer, start, start + length, this.depth, path);
	}
	string() {
		const length = this.length();
		const start = this.position;
		this.position += length;
		if (length <= 64) {
			const ascii = asciiString$1(this.buffer, start, length);
			if (ascii !== null) return ascii;
		}
		try {
			return textDecoder$1.decode(this.buffer.subarray(start, start + length));
		} catch {
			throw new CodecError$1("BAD_UTF8", this.path, "field is not valid UTF-8");
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
		const keyWidth = varintWidth$1(key);
		const raw = new Uint8Array(keyWidth + bodyLength);
		writeVarintAt$1(raw, 0, key);
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
		throw new CodecError$1("BAD_WIRE_TYPE", this.path, "unsupported wire type " + wire);
	}
};
function unsignedFromHalves$1(lo, hi, path) {
	if (hi > 2097151) throw new CodecError$1("PRECISION", path, "integer exceeds the safe range for a JS number");
	return hi * TWO_TO_32$1 + lo;
}
function signedFromHalves$1(lo, hi, path) {
	if ((hi & 2147483648) === 0) return unsignedFromHalves$1(lo, hi, path);
	let negatedLo = ~lo + 1 >>> 0;
	let negatedHi = ~hi >>> 0;
	if (negatedLo === 0) negatedHi = negatedHi + 1 >>> 0;
	const magnitude = negatedHi * TWO_TO_32$1 + negatedLo;
	if (magnitude > MAX_SAFE$1) throw new CodecError$1("PRECISION", path, "integer exceeds the safe range for a JS number");
	return -magnitude;
}
function requireInteger$1(value, path) {
	if (!Number.isFinite(value)) throw new CodecError$1("RANGE", path, "value is not finite");
	if (!Number.isInteger(value)) throw new CodecError$1("RANGE", path, "value is not an integer");
	return value;
}
var HEX$1 = "0123456789abcdef";
/** 512 two-character strings, so formatting a uuid is 16 lookups and a join. */
var HEX_PAIRS$1 = (() => {
	const pairs = new Array(256);
	for (let i = 0; i < 256; i++) pairs[i] = HEX$1[i >> 4] + HEX$1[i & 15];
	return pairs;
})();
/** -1 for any character that is not a hex digit. */
var HEX_VALUES$1 = (() => {
	const values = (/* @__PURE__ */ new Int8Array(128)).fill(-1);
	for (let i = 0; i < 16; i++) {
		values[HEX$1.charCodeAt(i)] = i;
		values["0123456789ABCDEF".charCodeAt(i)] = i;
	}
	return values;
})();
function uuidToBytes$1(value, path) {
	const out = /* @__PURE__ */ new Uint8Array(16);
	let written = 0;
	let high = -1;
	for (let index = 0; index < value.length; index++) {
		const code = value.charCodeAt(index);
		if (code === 45) continue;
		const digit = code < 128 ? HEX_VALUES$1[code] : -1;
		if (digit < 0 || written === 16) throw new CodecError$1("BAD_UUID", path, "not a uuid: " + value);
		if (high < 0) {
			high = digit;
			continue;
		}
		out[written++] = high << 4 | digit;
		high = -1;
	}
	if (written !== 16 || high >= 0) throw new CodecError$1("BAD_UUID", path, "not a uuid: " + value);
	return out;
}
function bytesToUuid$1(bytes, path) {
	if (bytes.length !== 16) throw new CodecError$1("BAD_UUID", path, "uuid must be 16 bytes, got " + bytes.length);
	return HEX_PAIRS$1[bytes[0]] + HEX_PAIRS$1[bytes[1]] + HEX_PAIRS$1[bytes[2]] + HEX_PAIRS$1[bytes[3]] + "-" + HEX_PAIRS$1[bytes[4]] + HEX_PAIRS$1[bytes[5]] + "-" + HEX_PAIRS$1[bytes[6]] + HEX_PAIRS$1[bytes[7]] + "-" + HEX_PAIRS$1[bytes[8]] + HEX_PAIRS$1[bytes[9]] + "-" + HEX_PAIRS$1[bytes[10]] + HEX_PAIRS$1[bytes[11]] + HEX_PAIRS$1[bytes[12]] + HEX_PAIRS$1[bytes[13]] + HEX_PAIRS$1[bytes[14]] + HEX_PAIRS$1[bytes[15]];
}
var MS_PER_DAY$1 = 864e5;
var MIN_FOUR_DIGIT_MS$1 = -719528 * MS_PER_DAY$1;
var MAX_FOUR_DIGIT_MS$1 = 2932897 * MS_PER_DAY$1 - 1;
/** -1 unless both characters are digits. */
function twoDigits$1(value, index) {
	const high = value.charCodeAt(index) - 48;
	const low = value.charCodeAt(index + 1) - 48;
	if (high < 0 || high > 9 || low < 0 || low > 9) return -1;
	return high * 10 + low;
}
function daysInMonth$1(year, month) {
	if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
	if (month === 4 || month === 6 || month === 9 || month === 11) return 30;
	return 31;
}
/** Howard Hinnant's days_from_civil; exact for every proleptic Gregorian date. */
function daysFromCivil$1(year, month, day) {
	const shiftedYear = month <= 2 ? year - 1 : year;
	const era = Math.floor(shiftedYear / 400);
	const yearOfEra = shiftedYear - era * 400;
	const monthIndex = month > 2 ? month - 3 : month + 9;
	const dayOfYear = Math.floor((153 * monthIndex + 2) / 5) + day - 1;
	const dayOfEra = yearOfEra * 365 + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100) + dayOfYear;
	return era * 146097 + dayOfEra - 719468;
}
/** The inverse, packed as year * 10000 + month * 100 + day to avoid an allocation. */
function civilFromDays$1(days) {
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
function parseIsoDate$1(value) {
	const yearHigh = twoDigits$1(value, 0);
	const yearLow = twoDigits$1(value, 2);
	const month = twoDigits$1(value, 5);
	const day = twoDigits$1(value, 8);
	if (yearHigh < 0 || yearLow < 0 || month < 0 || day < 0) return NaN;
	if (value.charCodeAt(4) !== 45 || value.charCodeAt(7) !== 45) return NaN;
	const year = yearHigh * 100 + yearLow;
	if (month < 1 || month > 12 || day < 1 || day > daysInMonth$1(year, month)) return NaN;
	return daysFromCivil$1(year, month, day);
}
/** "00".."99", so zero-padding is a lookup instead of a padStart call. */
var TWO_DIGIT_STRINGS$1 = (() => {
	const strings = new Array(100);
	for (let value = 0; value < 100; value++) strings[value] = String(Math.floor(value / 10)) + String(value % 10);
	return strings;
})();
function formatIsoDate$1(packed) {
	const year = Math.floor(packed / 1e4);
	const month = Math.floor(packed / 100) % 100;
	const day = packed % 100;
	return TWO_DIGIT_STRINGS$1[Math.floor(year / 100)] + TWO_DIGIT_STRINGS$1[year % 100] + "-" + TWO_DIGIT_STRINGS$1[month] + "-" + TWO_DIGIT_STRINGS$1[day];
}
var lastFormattedDays$1 = NaN;
var lastFormattedDate$1 = "";
function formatDateFromDays$1(days) {
	if (days === lastFormattedDays$1) return lastFormattedDate$1;
	const formatted = formatIsoDate$1(civilFromDays$1(days));
	lastFormattedDays$1 = days;
	lastFormattedDate$1 = formatted;
	return formatted;
}
/** Epoch ms for the exact toISOString shape YYYY-MM-DDTHH:MM:SS.sssZ, else NaN. */
function parseIsoUtcTimestamp$1(value) {
	if (value.length !== 24) return NaN;
	if (value.charCodeAt(10) !== 84 || value.charCodeAt(13) !== 58 || value.charCodeAt(16) !== 58 || value.charCodeAt(19) !== 46 || value.charCodeAt(23) !== 90) return NaN;
	const days = parseIsoDate$1(value);
	const hours = twoDigits$1(value, 11);
	const minutes = twoDigits$1(value, 14);
	const seconds = twoDigits$1(value, 17);
	const millisHigh = twoDigits$1(value, 20);
	const millisLow = value.charCodeAt(22) - 48;
	if (Number.isNaN(days) || hours < 0 || minutes < 0 || seconds < 0 || millisHigh < 0) return NaN;
	if (millisLow < 0 || millisLow > 9) return NaN;
	if (hours > 23 || minutes > 59 || seconds > 59) return NaN;
	const secondOfDay = hours * 3600 + minutes * 60 + seconds;
	return days * MS_PER_DAY$1 + secondOfDay * 1e3 + millisHigh * 10 + millisLow;
}
function timestampToMillis$1(value, path) {
	const fast = parseIsoUtcTimestamp$1(value);
	if (!Number.isNaN(fast)) return fast;
	const ms = Date.parse(value);
	if (Number.isNaN(ms)) throw new CodecError$1("BAD_TIMESTAMP", path, "invalid timestamp " + value);
	return ms;
}
function millisToTimestamp$1(ms, path) {
	if (Number.isInteger(ms) && ms >= MIN_FOUR_DIGIT_MS$1 && ms <= MAX_FOUR_DIGIT_MS$1) return formatIsoUtcTimestamp$1(ms);
	const date = new Date(ms);
	if (Number.isNaN(date.getTime())) throw new CodecError$1("BAD_TIMESTAMP", path, "timestamp out of range");
	return date.toISOString();
}
function formatIsoUtcTimestamp$1(ms) {
	const days = Math.floor(ms / MS_PER_DAY$1);
	const msOfDay = ms - days * MS_PER_DAY$1;
	const secondOfDay = Math.floor(msOfDay / 1e3);
	const millis = msOfDay - secondOfDay * 1e3;
	const hours = Math.floor(secondOfDay / 3600);
	const minutes = Math.floor(secondOfDay % 3600 / 60);
	const seconds = secondOfDay % 60;
	return formatDateFromDays$1(days) + "T" + TWO_DIGIT_STRINGS$1[hours] + ":" + TWO_DIGIT_STRINGS$1[minutes] + ":" + TWO_DIGIT_STRINGS$1[seconds] + "." + TWO_DIGIT_STRINGS$1[Math.floor(millis / 10)] + String(millis % 10) + "Z";
}
function canonicalJson(value) {
	return JSON.stringify(sortJsonKeys(value));
}
function sortJsonKeys(value) {
	if (Array.isArray(value)) return value.map(sortJsonKeys);
	if (value === null || typeof value !== "object") return value;
	const source = value;
	const sorted = {};
	for (const key of Object.keys(source).sort()) sorted[key] = sortJsonKeys(source[key]);
	return sorted;
}
function parseJson(text, path) {
	try {
		return JSON.parse(text);
	} catch (error) {
		throw new CodecError$1("BAD_JSON", path, "invalid JSON: " + error.message);
	}
}
/**
* Sort captured unknown fields by tag so they can be interleaved into the known
* fields' ascending order. Array.prototype.sort is stable, so several entries
* sharing a tag keep their original relative order.
*/
function prepareUnknown$1(unknown, known, path) {
	if (unknown === void 0 || unknown.length === 0) return [];
	for (const field of unknown) if (known.has(field.tag)) throw new CodecError$1("UNKNOWN_COLLISION", path, "unknown field carries tag " + field.tag + ", which this message declares");
	return [...unknown].sort((a, b) => a.tag - b.tag);
}
/** Emit every pending unknown field whose tag precedes the given tag. */
function flushUnknownBefore$1(writer, unknown, index, tag) {
	let cursor = index;
	while (cursor < unknown.length && unknown[cursor].tag < tag) {
		writer.raw(unknown[cursor].raw);
		cursor++;
	}
	return cursor;
}
function flushUnknownRest$1(writer, unknown, index) {
	for (let cursor = index; cursor < unknown.length; cursor++) writer.raw(unknown[cursor].raw);
}
/**
* Capture a field the schema does not declare. Retired tags are dropped instead:
* they are known-dead, so preserving them would grow every row forever.
*/
function captureUnknown$1(reader, key, tag, wire, into, retired) {
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
function missingField$1(path, name, tag) {
	return new CodecError$1("MISSING_FIELD", path, "required field '" + name + "' (tag " + tag + ") is absent");
}
function expectWire$1(actual, expected, path) {
	if (actual === expected) return;
	throw new CodecError$1("WIRE_MISMATCH", path, "expected wire type " + expected + ", got " + actual);
}
function readSignedField$1(reader, wire, path) {
	expectWire$1(wire, 0, path);
	return reader.varintSigned(path);
}
function readUnsignedField$1(reader, wire, path) {
	expectWire$1(wire, 0, path);
	return reader.varintUnsigned(path);
}
function readStringField$1(reader, wire, path) {
	expectWire$1(wire, 2, path);
	return reader.string();
}
function readBytesField$1(reader, wire, path) {
	expectWire$1(wire, 2, path);
	return reader.bytes();
}
function readPackedSigned(reader, wire, path, into) {
	if (wire === 2) {
		const body = reader.packed(path);
		while (body.hasMore()) into.push(body.varintSigned(path));
		return;
	}
	into.push(readSignedField$1(reader, wire, path));
}
var KNOWN_NDay = /* @__PURE__ */ new Set([1, 2]);
var RETIRED_NDay = /* @__PURE__ */ new Set([]);
function writeNDay(w, value, path) {
	const unknown = prepareUnknown$1(value.$unknown, KNOWN_NDay, path);
	let pending = 0;
	pending = flushUnknownBefore$1(w, unknown, pending, 1);
	w.key(1, 2);
	w.string(value.day);
	pending = flushUnknownBefore$1(w, unknown, pending, 2);
	if (value.nth_of_period !== null && value.nth_of_period !== void 0) {
		const present = value.nth_of_period;
		w.key(2, 0);
		w.varintNumber(requireInteger$1(present, path + ".nth_of_period"));
	}
	flushUnknownRest$1(w, unknown, pending);
}
function readNDay(r, path) {
	let field1;
	let field2;
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1:
				field1 = readStringField$1(r, wire, path + ".day");
				break;
			case 2:
				field2 = readSignedField$1(r, wire, path + ".nth_of_period");
				break;
			default: unknown = captureUnknown$1(r, wireKey, tag, wire, unknown, RETIRED_NDay);
		}
	}
	if (field1 === void 0) throw missingField$1(path, "day", 1);
	const result = {
		day: field1,
		nth_of_period: field2
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
var KNOWN_RecurrenceRule = /* @__PURE__ */ new Set([
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	9
]);
var RETIRED_RecurrenceRule = /* @__PURE__ */ new Set([]);
function writeRecurrenceRule(w, value, path) {
	const unknown = prepareUnknown$1(value.$unknown, KNOWN_RecurrenceRule, path);
	let pending = 0;
	pending = flushUnknownBefore$1(w, unknown, pending, 1);
	w.key(1, 2);
	w.string(value.frequency);
	pending = flushUnknownBefore$1(w, unknown, pending, 2);
	if (value.interval !== null && value.interval !== void 0) {
		const present = value.interval;
		w.key(2, 0);
		w.varintNumber(requireInteger$1(present, path + ".interval"));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 3);
	if (value.until !== null && value.until !== void 0) {
		const present = value.until;
		w.key(3, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 4);
	if (value.count !== null && value.count !== void 0) {
		const present = value.count;
		w.key(4, 0);
		w.varintNumber(requireInteger$1(present, path + ".count"));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 5);
	if (value.first_day_of_week !== null && value.first_day_of_week !== void 0) {
		const present = value.first_day_of_week;
		w.key(5, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 6);
	if (value.by_day !== null && value.by_day !== void 0) {
		const present = value.by_day;
		w.key(6, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			{
				const nestedOffset = w.beginNested();
				writeNDay(w, item, path + ".by_day");
				w.endNested(nestedOffset);
			}
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 7);
	if (value.by_month_day !== null && value.by_month_day !== void 0) {
		const present = value.by_month_day;
		w.key(7, 2);
		const wrapperOffset = w.beginNested();
		if (present.length > 0) {
			w.key(1, 2);
			const packedOffset = w.beginNested();
			for (const item of present) w.varintNumber(requireInteger$1(item, path + ".by_month_day"));
			w.endNested(packedOffset);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 8);
	if (value.by_month !== null && value.by_month !== void 0) {
		const present = value.by_month;
		w.key(8, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 9);
	if (value.by_set_position !== null && value.by_set_position !== void 0) {
		const present = value.by_set_position;
		w.key(9, 2);
		const wrapperOffset = w.beginNested();
		if (present.length > 0) {
			w.key(1, 2);
			const packedOffset = w.beginNested();
			for (const item of present) w.varintNumber(requireInteger$1(item, path + ".by_set_position"));
			w.endNested(packedOffset);
		}
		w.endNested(wrapperOffset);
	}
	flushUnknownRest$1(w, unknown, pending);
}
function readRecurrenceRule(r, path) {
	let field1;
	let field2;
	let field3;
	let field4;
	let field5;
	let field6;
	let field7;
	let field8;
	let field9;
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1:
				field1 = readStringField$1(r, wire, path + ".frequency");
				break;
			case 2:
				field2 = readSignedField$1(r, wire, path + ".interval");
				break;
			case 3:
				field3 = readStringField$1(r, wire, path + ".until");
				break;
			case 4:
				field4 = readSignedField$1(r, wire, path + ".count");
				break;
			case 5:
				field5 = readStringField$1(r, wire, path + ".first_day_of_week");
				break;
			case 6: {
				expectWire$1(wire, 2, path + ".by_day");
				const wrapper = r.subMessage(path + ".by_day");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readNDay((expectWire$1(innerWire, 2, path + ".by_day"), wrapper.subMessage(path + ".by_day")), path + ".by_day"));
				}
				field6 = items;
				break;
			}
			case 7: {
				expectWire$1(wire, 2, path + ".by_month_day");
				const wrapper = r.subMessage(path + ".by_month_day");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					const raw = [];
					readPackedSigned(wrapper, innerWire, path + ".by_month_day", raw);
					for (const item of raw) items.push(item);
				}
				field7 = items;
				break;
			}
			case 8: {
				expectWire$1(wire, 2, path + ".by_month");
				const wrapper = r.subMessage(path + ".by_month");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$1(wrapper, innerWire, path + ".by_month"));
				}
				field8 = items;
				break;
			}
			case 9: {
				expectWire$1(wire, 2, path + ".by_set_position");
				const wrapper = r.subMessage(path + ".by_set_position");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					const raw = [];
					readPackedSigned(wrapper, innerWire, path + ".by_set_position", raw);
					for (const item of raw) items.push(item);
				}
				field9 = items;
				break;
			}
			default: unknown = captureUnknown$1(r, wireKey, tag, wire, unknown, RETIRED_RecurrenceRule);
		}
	}
	if (field1 === void 0) throw missingField$1(path, "frequency", 1);
	const result = {
		frequency: field1,
		interval: field2,
		until: field3,
		count: field4,
		first_day_of_week: field5,
		by_day: field6,
		by_month_day: field7,
		by_month: field8,
		by_set_position: field9
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
var KNOWN_Event = /* @__PURE__ */ new Set([
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
	28
]);
var RETIRED_Event = /* @__PURE__ */ new Set([]);
function encodeEvent(value) {
	const writer = new Writer$1();
	writeEvent(writer, value, "Event");
	return writer.finish();
}
function writeEvent(w, value, path) {
	const unknown = prepareUnknown$1(value.$unknown, KNOWN_Event, path);
	let pending = 0;
	pending = flushUnknownBefore$1(w, unknown, pending, 1);
	w.key(1, 2);
	w.lengthDelimited(uuidToBytes$1(value.id, path + ".id"));
	pending = flushUnknownBefore$1(w, unknown, pending, 2);
	w.key(2, 2);
	w.string(value.uid);
	pending = flushUnknownBefore$1(w, unknown, pending, 3);
	w.key(3, 2);
	w.string(value.title);
	pending = flushUnknownBefore$1(w, unknown, pending, 4);
	if (value.description !== null && value.description !== void 0) {
		const present = value.description;
		w.key(4, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 5);
	w.key(5, 2);
	w.string(value.start);
	pending = flushUnknownBefore$1(w, unknown, pending, 6);
	if (value.duration !== null && value.duration !== void 0) {
		const present = value.duration;
		w.key(6, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 7);
	if (value.time_zone !== null && value.time_zone !== void 0) {
		const present = value.time_zone;
		w.key(7, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 8);
	w.key(8, 0);
	w.varintNumber(value.show_without_time ? 1 : 0);
	pending = flushUnknownBefore$1(w, unknown, pending, 9);
	if (value.status !== null && value.status !== void 0) {
		const present = value.status;
		w.key(9, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 10);
	if (value.free_busy_status !== null && value.free_busy_status !== void 0) {
		const present = value.free_busy_status;
		w.key(10, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 11);
	if (value.privacy !== null && value.privacy !== void 0) {
		const present = value.privacy;
		w.key(11, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 12);
	if (value.priority !== null && value.priority !== void 0) {
		const present = value.priority;
		w.key(12, 0);
		w.varintNumber(requireInteger$1(present, path + ".priority"));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 13);
	if (value.color !== null && value.color !== void 0) {
		const present = value.color;
		w.key(13, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 14);
	if (value.sequence !== null && value.sequence !== void 0) {
		const present = value.sequence;
		w.key(14, 0);
		w.varintNumber(requireInteger$1(present, path + ".sequence"));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 15);
	if (value.keywords !== null && value.keywords !== void 0) {
		const present = value.keywords;
		w.key(15, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 16);
	if (value.participants !== null && value.participants !== void 0) {
		const present = value.participants;
		w.key(16, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 17);
	if (value.locations !== null && value.locations !== void 0) {
		const present = value.locations;
		w.key(17, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 18);
	if (value.virtual_locations !== null && value.virtual_locations !== void 0) {
		const present = value.virtual_locations;
		w.key(18, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 19);
	if (value.alerts !== null && value.alerts !== void 0) {
		const present = value.alerts;
		w.key(19, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 20);
	if (value.links !== null && value.links !== void 0) {
		const present = value.links;
		w.key(20, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 21);
	if (value.related_to !== null && value.related_to !== void 0) {
		const present = value.related_to;
		w.key(21, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 22);
	if (value.localizations !== null && value.localizations !== void 0) {
		const present = value.localizations;
		w.key(22, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 23);
	if (value.recurrence_overrides !== null && value.recurrence_overrides !== void 0) {
		const present = value.recurrence_overrides;
		w.key(23, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 24);
	if (value.recurrence_rules !== null && value.recurrence_rules !== void 0) {
		const present = value.recurrence_rules;
		w.key(24, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			{
				const nestedOffset = w.beginNested();
				writeRecurrenceRule(w, item, path + ".recurrence_rules");
				w.endNested(nestedOffset);
			}
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 25);
	if (value.excluded_recurrence_rules !== null && value.excluded_recurrence_rules !== void 0) {
		const present = value.excluded_recurrence_rules;
		w.key(25, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			{
				const nestedOffset = w.beginNested();
				writeRecurrenceRule(w, item, path + ".excluded_recurrence_rules");
				w.endNested(nestedOffset);
			}
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 26);
	w.key(26, 0);
	w.varintNumber(value.deleted ? 1 : 0);
	pending = flushUnknownBefore$1(w, unknown, pending, 27);
	w.key(27, 0);
	w.varintNumber(timestampToMillis$1(value.created_at, path + ".created_at"));
	pending = flushUnknownBefore$1(w, unknown, pending, 28);
	w.key(28, 0);
	w.varintNumber(timestampToMillis$1(value.updated_at, path + ".updated_at"));
	flushUnknownRest$1(w, unknown, pending);
}
function decodeEvent(bytes) {
	return readEvent(Reader$1.of(bytes, "Event"), "Event");
}
function readEvent(r, path) {
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
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1:
				field1 = bytesToUuid$1(readBytesField$1(r, wire, path + ".id"), path + ".id");
				break;
			case 2:
				field2 = readStringField$1(r, wire, path + ".uid");
				break;
			case 3:
				field3 = readStringField$1(r, wire, path + ".title");
				break;
			case 4:
				field4 = readStringField$1(r, wire, path + ".description");
				break;
			case 5:
				field5 = readStringField$1(r, wire, path + ".start");
				break;
			case 6:
				field6 = readStringField$1(r, wire, path + ".duration");
				break;
			case 7:
				field7 = readStringField$1(r, wire, path + ".time_zone");
				break;
			case 8:
				field8 = readUnsignedField$1(r, wire, path + ".show_without_time") !== 0;
				break;
			case 9:
				field9 = readStringField$1(r, wire, path + ".status");
				break;
			case 10:
				field10 = readStringField$1(r, wire, path + ".free_busy_status");
				break;
			case 11:
				field11 = readStringField$1(r, wire, path + ".privacy");
				break;
			case 12:
				field12 = readSignedField$1(r, wire, path + ".priority");
				break;
			case 13:
				field13 = readStringField$1(r, wire, path + ".color");
				break;
			case 14:
				field14 = readSignedField$1(r, wire, path + ".sequence");
				break;
			case 15: {
				expectWire$1(wire, 2, path + ".keywords");
				const wrapper = r.subMessage(path + ".keywords");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$1(wrapper, innerWire, path + ".keywords"));
				}
				field15 = items;
				break;
			}
			case 16:
				field16 = parseJson(readStringField$1(r, wire, path + ".participants"), path + ".participants");
				break;
			case 17:
				field17 = parseJson(readStringField$1(r, wire, path + ".locations"), path + ".locations");
				break;
			case 18:
				field18 = parseJson(readStringField$1(r, wire, path + ".virtual_locations"), path + ".virtual_locations");
				break;
			case 19:
				field19 = parseJson(readStringField$1(r, wire, path + ".alerts"), path + ".alerts");
				break;
			case 20:
				field20 = parseJson(readStringField$1(r, wire, path + ".links"), path + ".links");
				break;
			case 21:
				field21 = parseJson(readStringField$1(r, wire, path + ".related_to"), path + ".related_to");
				break;
			case 22:
				field22 = parseJson(readStringField$1(r, wire, path + ".localizations"), path + ".localizations");
				break;
			case 23:
				field23 = parseJson(readStringField$1(r, wire, path + ".recurrence_overrides"), path + ".recurrence_overrides");
				break;
			case 24: {
				expectWire$1(wire, 2, path + ".recurrence_rules");
				const wrapper = r.subMessage(path + ".recurrence_rules");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readRecurrenceRule((expectWire$1(innerWire, 2, path + ".recurrence_rules"), wrapper.subMessage(path + ".recurrence_rules")), path + ".recurrence_rules"));
				}
				field24 = items;
				break;
			}
			case 25: {
				expectWire$1(wire, 2, path + ".excluded_recurrence_rules");
				const wrapper = r.subMessage(path + ".excluded_recurrence_rules");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readRecurrenceRule((expectWire$1(innerWire, 2, path + ".excluded_recurrence_rules"), wrapper.subMessage(path + ".excluded_recurrence_rules")), path + ".excluded_recurrence_rules"));
				}
				field25 = items;
				break;
			}
			case 26:
				field26 = readUnsignedField$1(r, wire, path + ".deleted") !== 0;
				break;
			case 27:
				field27 = millisToTimestamp$1(readSignedField$1(r, wire, path + ".created_at"), path + ".created_at");
				break;
			case 28:
				field28 = millisToTimestamp$1(readSignedField$1(r, wire, path + ".updated_at"), path + ".updated_at");
				break;
			default: unknown = captureUnknown$1(r, wireKey, tag, wire, unknown, RETIRED_Event);
		}
	}
	if (field1 === void 0) throw missingField$1(path, "id", 1);
	if (field2 === void 0) throw missingField$1(path, "uid", 2);
	if (field3 === void 0) throw missingField$1(path, "title", 3);
	if (field5 === void 0) throw missingField$1(path, "start", 5);
	if (field8 === void 0) throw missingField$1(path, "show_without_time", 8);
	if (field26 === void 0) throw missingField$1(path, "deleted", 26);
	if (field27 === void 0) throw missingField$1(path, "created_at", 27);
	if (field28 === void 0) throw missingField$1(path, "updated_at", 28);
	const result = {
		id: field1,
		uid: field2,
		title: field3,
		description: field4,
		start: field5,
		duration: field6,
		time_zone: field7,
		show_without_time: field8,
		status: field9,
		free_busy_status: field10,
		privacy: field11,
		priority: field12,
		color: field13,
		sequence: field14,
		keywords: field15,
		participants: field16,
		locations: field17,
		virtual_locations: field18,
		alerts: field19,
		links: field20,
		related_to: field21,
		localizations: field22,
		recurrence_overrides: field23,
		recurrence_rules: field24,
		excluded_recurrence_rules: field25,
		deleted: field26,
		created_at: field27,
		updated_at: field28
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
var KNOWN_EventVersion = /* @__PURE__ */ new Set([
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
	29
]);
var RETIRED_EventVersion = /* @__PURE__ */ new Set([]);
function encodeEventVersion(value) {
	const writer = new Writer$1();
	writeEventVersion(writer, value, "EventVersion");
	return writer.finish();
}
function writeEventVersion(w, value, path) {
	const unknown = prepareUnknown$1(value.$unknown, KNOWN_EventVersion, path);
	let pending = 0;
	pending = flushUnknownBefore$1(w, unknown, pending, 1);
	w.key(1, 2);
	w.lengthDelimited(uuidToBytes$1(value.id, path + ".id"));
	pending = flushUnknownBefore$1(w, unknown, pending, 2);
	w.key(2, 2);
	w.lengthDelimited(uuidToBytes$1(value.event_id, path + ".event_id"));
	pending = flushUnknownBefore$1(w, unknown, pending, 3);
	w.key(3, 2);
	w.string(value.uid);
	pending = flushUnknownBefore$1(w, unknown, pending, 4);
	w.key(4, 2);
	w.string(value.title);
	pending = flushUnknownBefore$1(w, unknown, pending, 5);
	if (value.description !== null && value.description !== void 0) {
		const present = value.description;
		w.key(5, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 6);
	w.key(6, 2);
	w.string(value.start);
	pending = flushUnknownBefore$1(w, unknown, pending, 7);
	if (value.duration !== null && value.duration !== void 0) {
		const present = value.duration;
		w.key(7, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 8);
	if (value.time_zone !== null && value.time_zone !== void 0) {
		const present = value.time_zone;
		w.key(8, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 9);
	w.key(9, 0);
	w.varintNumber(value.show_without_time ? 1 : 0);
	pending = flushUnknownBefore$1(w, unknown, pending, 10);
	if (value.status !== null && value.status !== void 0) {
		const present = value.status;
		w.key(10, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 11);
	if (value.free_busy_status !== null && value.free_busy_status !== void 0) {
		const present = value.free_busy_status;
		w.key(11, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 12);
	if (value.privacy !== null && value.privacy !== void 0) {
		const present = value.privacy;
		w.key(12, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 13);
	if (value.priority !== null && value.priority !== void 0) {
		const present = value.priority;
		w.key(13, 0);
		w.varintNumber(requireInteger$1(present, path + ".priority"));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 14);
	if (value.color !== null && value.color !== void 0) {
		const present = value.color;
		w.key(14, 2);
		w.string(present);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 15);
	if (value.sequence !== null && value.sequence !== void 0) {
		const present = value.sequence;
		w.key(15, 0);
		w.varintNumber(requireInteger$1(present, path + ".sequence"));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 16);
	if (value.keywords !== null && value.keywords !== void 0) {
		const present = value.keywords;
		w.key(16, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 17);
	if (value.participants !== null && value.participants !== void 0) {
		const present = value.participants;
		w.key(17, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 18);
	if (value.locations !== null && value.locations !== void 0) {
		const present = value.locations;
		w.key(18, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 19);
	if (value.virtual_locations !== null && value.virtual_locations !== void 0) {
		const present = value.virtual_locations;
		w.key(19, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 20);
	if (value.alerts !== null && value.alerts !== void 0) {
		const present = value.alerts;
		w.key(20, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 21);
	if (value.links !== null && value.links !== void 0) {
		const present = value.links;
		w.key(21, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 22);
	if (value.related_to !== null && value.related_to !== void 0) {
		const present = value.related_to;
		w.key(22, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 23);
	if (value.localizations !== null && value.localizations !== void 0) {
		const present = value.localizations;
		w.key(23, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 24);
	if (value.recurrence_overrides !== null && value.recurrence_overrides !== void 0) {
		const present = value.recurrence_overrides;
		w.key(24, 2);
		w.string(canonicalJson(present));
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 25);
	if (value.recurrence_rules !== null && value.recurrence_rules !== void 0) {
		const present = value.recurrence_rules;
		w.key(25, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			{
				const nestedOffset = w.beginNested();
				writeRecurrenceRule(w, item, path + ".recurrence_rules");
				w.endNested(nestedOffset);
			}
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 26);
	if (value.excluded_recurrence_rules !== null && value.excluded_recurrence_rules !== void 0) {
		const present = value.excluded_recurrence_rules;
		w.key(26, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			{
				const nestedOffset = w.beginNested();
				writeRecurrenceRule(w, item, path + ".excluded_recurrence_rules");
				w.endNested(nestedOffset);
			}
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore$1(w, unknown, pending, 27);
	w.key(27, 0);
	w.varintNumber(value.deleted ? 1 : 0);
	pending = flushUnknownBefore$1(w, unknown, pending, 28);
	w.key(28, 0);
	w.varintNumber(timestampToMillis$1(value.created_at, path + ".created_at"));
	pending = flushUnknownBefore$1(w, unknown, pending, 29);
	if (value.parent_ids !== null && value.parent_ids !== void 0) {
		const present = value.parent_ids;
		w.key(29, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.lengthDelimited(uuidToBytes$1(item, path + ".parent_ids"));
		}
		w.endNested(wrapperOffset);
	}
	flushUnknownRest$1(w, unknown, pending);
}
function decodeEventVersion(bytes) {
	return readEventVersion(Reader$1.of(bytes, "EventVersion"), "EventVersion");
}
function readEventVersion(r, path) {
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
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1:
				field1 = bytesToUuid$1(readBytesField$1(r, wire, path + ".id"), path + ".id");
				break;
			case 2:
				field2 = bytesToUuid$1(readBytesField$1(r, wire, path + ".event_id"), path + ".event_id");
				break;
			case 3:
				field3 = readStringField$1(r, wire, path + ".uid");
				break;
			case 4:
				field4 = readStringField$1(r, wire, path + ".title");
				break;
			case 5:
				field5 = readStringField$1(r, wire, path + ".description");
				break;
			case 6:
				field6 = readStringField$1(r, wire, path + ".start");
				break;
			case 7:
				field7 = readStringField$1(r, wire, path + ".duration");
				break;
			case 8:
				field8 = readStringField$1(r, wire, path + ".time_zone");
				break;
			case 9:
				field9 = readUnsignedField$1(r, wire, path + ".show_without_time") !== 0;
				break;
			case 10:
				field10 = readStringField$1(r, wire, path + ".status");
				break;
			case 11:
				field11 = readStringField$1(r, wire, path + ".free_busy_status");
				break;
			case 12:
				field12 = readStringField$1(r, wire, path + ".privacy");
				break;
			case 13:
				field13 = readSignedField$1(r, wire, path + ".priority");
				break;
			case 14:
				field14 = readStringField$1(r, wire, path + ".color");
				break;
			case 15:
				field15 = readSignedField$1(r, wire, path + ".sequence");
				break;
			case 16: {
				expectWire$1(wire, 2, path + ".keywords");
				const wrapper = r.subMessage(path + ".keywords");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField$1(wrapper, innerWire, path + ".keywords"));
				}
				field16 = items;
				break;
			}
			case 17:
				field17 = parseJson(readStringField$1(r, wire, path + ".participants"), path + ".participants");
				break;
			case 18:
				field18 = parseJson(readStringField$1(r, wire, path + ".locations"), path + ".locations");
				break;
			case 19:
				field19 = parseJson(readStringField$1(r, wire, path + ".virtual_locations"), path + ".virtual_locations");
				break;
			case 20:
				field20 = parseJson(readStringField$1(r, wire, path + ".alerts"), path + ".alerts");
				break;
			case 21:
				field21 = parseJson(readStringField$1(r, wire, path + ".links"), path + ".links");
				break;
			case 22:
				field22 = parseJson(readStringField$1(r, wire, path + ".related_to"), path + ".related_to");
				break;
			case 23:
				field23 = parseJson(readStringField$1(r, wire, path + ".localizations"), path + ".localizations");
				break;
			case 24:
				field24 = parseJson(readStringField$1(r, wire, path + ".recurrence_overrides"), path + ".recurrence_overrides");
				break;
			case 25: {
				expectWire$1(wire, 2, path + ".recurrence_rules");
				const wrapper = r.subMessage(path + ".recurrence_rules");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readRecurrenceRule((expectWire$1(innerWire, 2, path + ".recurrence_rules"), wrapper.subMessage(path + ".recurrence_rules")), path + ".recurrence_rules"));
				}
				field25 = items;
				break;
			}
			case 26: {
				expectWire$1(wire, 2, path + ".excluded_recurrence_rules");
				const wrapper = r.subMessage(path + ".excluded_recurrence_rules");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readRecurrenceRule((expectWire$1(innerWire, 2, path + ".excluded_recurrence_rules"), wrapper.subMessage(path + ".excluded_recurrence_rules")), path + ".excluded_recurrence_rules"));
				}
				field26 = items;
				break;
			}
			case 27:
				field27 = readUnsignedField$1(r, wire, path + ".deleted") !== 0;
				break;
			case 28:
				field28 = millisToTimestamp$1(readSignedField$1(r, wire, path + ".created_at"), path + ".created_at");
				break;
			case 29: {
				expectWire$1(wire, 2, path + ".parent_ids");
				const wrapper = r.subMessage(path + ".parent_ids");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(bytesToUuid$1(readBytesField$1(wrapper, innerWire, path + ".parent_ids"), path + ".parent_ids"));
				}
				field29 = items;
				break;
			}
			default: unknown = captureUnknown$1(r, wireKey, tag, wire, unknown, RETIRED_EventVersion);
		}
	}
	if (field1 === void 0) throw missingField$1(path, "id", 1);
	if (field2 === void 0) throw missingField$1(path, "event_id", 2);
	if (field3 === void 0) throw missingField$1(path, "uid", 3);
	if (field4 === void 0) throw missingField$1(path, "title", 4);
	if (field6 === void 0) throw missingField$1(path, "start", 6);
	if (field9 === void 0) throw missingField$1(path, "show_without_time", 9);
	if (field27 === void 0) throw missingField$1(path, "deleted", 27);
	if (field28 === void 0) throw missingField$1(path, "created_at", 28);
	const result = {
		id: field1,
		event_id: field2,
		uid: field3,
		title: field4,
		description: field5,
		start: field6,
		duration: field7,
		time_zone: field8,
		show_without_time: field9,
		status: field10,
		free_busy_status: field11,
		privacy: field12,
		priority: field13,
		color: field14,
		sequence: field15,
		keywords: field16,
		participants: field17,
		locations: field18,
		virtual_locations: field19,
		alerts: field20,
		links: field21,
		related_to: field22,
		localizations: field23,
		recurrence_overrides: field24,
		recurrence_rules: field25,
		excluded_recurrence_rules: field26,
		deleted: field27,
		created_at: field28,
		parent_ids: field29
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
//#endregion
//#region src/vault/collections/calendar.ts
/** jsCalendar UID for a new event; stable across instances and imports. */
function mintUid$1() {
	return crypto.randomUUID();
}
var calendarCollection = {
	name: "calendar",
	encodeRow: encodeEvent,
	decodeRow: decodeEvent,
	encodeVersion: encodeEventVersion,
	decodeVersion: decodeEventVersion,
	prepare(input, existing, id, now) {
		return {
			title: "",
			start: now.slice(0, 19),
			show_without_time: false,
			deleted: false,
			...input,
			id,
			uid: input.uid || existing?.uid || mintUid$1(),
			created_at: input.created_at || existing?.created_at || now,
			updated_at: now
		};
	},
	versionOf(versionId, row, parentIds, createdAt) {
		const { id, created_at, updated_at, $unknown, ...rest } = row;
		return {
			...rest,
			id: versionId,
			event_id: id,
			created_at: createdAt,
			parent_ids: parentIds.length > 0 ? parentIds : void 0
		};
	},
	rowFieldsOf(version) {
		const { id, event_id, created_at, parent_ids, $unknown, ...rest } = version;
		return rest;
	},
	merge: lastWriterWins,
	fields: {
		title: {
			kind: "string",
			get: (row) => row.title
		},
		description: {
			kind: "string",
			get: (row) => row.description
		},
		status: {
			kind: "string",
			get: (row) => row.status
		},
		privacy: {
			kind: "string",
			get: (row) => row.privacy
		},
		free_busy_status: {
			kind: "string",
			get: (row) => row.free_busy_status
		},
		priority: {
			kind: "int",
			get: (row) => row.priority
		},
		keywords: {
			kind: "stringList",
			get: (row) => row.keywords
		},
		start: {
			kind: "date",
			get: (row) => row.start
		},
		deleted: {
			kind: "bool",
			get: (row) => row.deleted
		},
		created_at: {
			kind: "date",
			get: (row) => row.created_at
		},
		updated_at: {
			kind: "date",
			get: (row) => row.updated_at
		}
	},
	searchText: (row) => [
		row.title,
		row.description ?? "",
		...list(row.keywords)
	],
	matchesScope(row, scope) {
		if (scope === "ALL") return true;
		if (scope === "TRASHED") return row.deleted;
		return !row.deleted;
	},
	comparators: {
		START: (a, b) => compareDates(a.start, b.start),
		TITLE: (a, b) => compareText(a.title, b.title),
		CREATED_AT: (a, b) => compareDates(a.created_at, b.created_at),
		UPDATED_AT: (a, b) => compareDates(a.updated_at, b.updated_at)
	},
	defaultSort: [{
		field: "START",
		direction: "ASC"
	}]
};
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
function readPackedDouble(reader, wire, path, into) {
	if (wire === 2) {
		const body = reader.packed(path);
		while (body.hasMore()) into.push(body.double());
		return;
	}
	into.push(readDoubleField(reader, wire, path));
}
var KNOWN_Embedding = /* @__PURE__ */ new Set([
	1,
	2,
	3,
	4
]);
var RETIRED_Embedding = /* @__PURE__ */ new Set([]);
function writeEmbedding(w, value, path) {
	const unknown = prepareUnknown(value.$unknown, KNOWN_Embedding, path);
	let pending = 0;
	pending = flushUnknownBefore(w, unknown, pending, 1);
	w.key(1, 2);
	w.string(value.model);
	pending = flushUnknownBefore(w, unknown, pending, 2);
	w.key(2, 0);
	w.varintNumber(requireInteger(value.dim, path + ".dim"));
	pending = flushUnknownBefore(w, unknown, pending, 3);
	if (value.vector.length > 0) {
		w.key(3, 2);
		const packedOffset = w.beginNested();
		for (const item of value.vector) w.double(requireFinite(item, path + ".vector"));
		w.endNested(packedOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 4);
	w.key(4, 0);
	w.varintNumber(timestampToMillis(value.created_at, path + ".created_at"));
	flushUnknownRest(w, unknown, pending);
}
function readEmbedding(r, path) {
	let field1;
	let field2;
	const field3 = [];
	let field4;
	let unknown;
	while (r.hasMore()) {
		const wireKey = r.key();
		const tag = wireKey >>> 3;
		const wire = wireKey & 7;
		switch (tag) {
			case 1:
				field1 = readStringField(r, wire, path + ".model");
				break;
			case 2:
				field2 = readSignedField(r, wire, path + ".dim");
				break;
			case 3:
				readPackedDouble(r, wire, path + ".vector", field3);
				break;
			case 4:
				field4 = millisToTimestamp(readSignedField(r, wire, path + ".created_at"), path + ".created_at");
				break;
			default: unknown = captureUnknown(r, wireKey, tag, wire, unknown, RETIRED_Embedding);
		}
	}
	if (field1 === void 0) throw missingField(path, "model", 1);
	if (field2 === void 0) throw missingField(path, "dim", 2);
	if (field4 === void 0) throw missingField(path, "created_at", 4);
	const result = {
		model: field1,
		dim: field2,
		vector: field3,
		created_at: field4
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
var KNOWN_Memory = /* @__PURE__ */ new Set([
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
	11
]);
var RETIRED_Memory = /* @__PURE__ */ new Set([]);
function encodeMemory(value) {
	const writer = new Writer();
	writeMemory(writer, value, "Memory");
	return writer.finish();
}
function writeMemory(w, value, path) {
	const unknown = prepareUnknown(value.$unknown, KNOWN_Memory, path);
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
	if (value.title !== null && value.title !== void 0) {
		const present = value.title;
		w.key(4, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 5);
	if (value.source_text !== null && value.source_text !== void 0) {
		const present = value.source_text;
		w.key(5, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 6);
	if (value.file !== null && value.file !== void 0) {
		const present = value.file;
		w.key(6, 2);
		w.lengthDelimited(uuidToBytes(present, path + ".file"));
	}
	pending = flushUnknownBefore(w, unknown, pending, 7);
	if (value.tags !== null && value.tags !== void 0) {
		const present = value.tags;
		w.key(7, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 8);
	if (value.embedding !== null && value.embedding !== void 0) {
		const present = value.embedding;
		w.key(8, 2);
		{
			const nestedOffset = w.beginNested();
			writeEmbedding(w, present, path + ".embedding");
			w.endNested(nestedOffset);
		}
	}
	pending = flushUnknownBefore(w, unknown, pending, 9);
	w.key(9, 0);
	w.varintNumber(value.deleted ? 1 : 0);
	pending = flushUnknownBefore(w, unknown, pending, 10);
	w.key(10, 0);
	w.varintNumber(timestampToMillis(value.created_at, path + ".created_at"));
	pending = flushUnknownBefore(w, unknown, pending, 11);
	w.key(11, 0);
	w.varintNumber(timestampToMillis(value.updated_at, path + ".updated_at"));
	flushUnknownRest(w, unknown, pending);
}
function decodeMemory(bytes) {
	return readMemory(Reader.of(bytes, "Memory"), "Memory");
}
function readMemory(r, path) {
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
				field4 = readStringField(r, wire, path + ".title");
				break;
			case 5:
				field5 = readStringField(r, wire, path + ".source_text");
				break;
			case 6:
				field6 = bytesToUuid(readBytesField(r, wire, path + ".file"), path + ".file");
				break;
			case 7: {
				expectWire(wire, 2, path + ".tags");
				const wrapper = r.subMessage(path + ".tags");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField(wrapper, innerWire, path + ".tags"));
				}
				field7 = items;
				break;
			}
			case 8:
				field8 = readEmbedding((expectWire(wire, 2, path + ".embedding"), r.subMessage(path + ".embedding")), path + ".embedding");
				break;
			case 9:
				field9 = readUnsignedField(r, wire, path + ".deleted") !== 0;
				break;
			case 10:
				field10 = millisToTimestamp(readSignedField(r, wire, path + ".created_at"), path + ".created_at");
				break;
			case 11:
				field11 = millisToTimestamp(readSignedField(r, wire, path + ".updated_at"), path + ".updated_at");
				break;
			default: unknown = captureUnknown(r, wireKey, tag, wire, unknown, RETIRED_Memory);
		}
	}
	if (field1 === void 0) throw missingField(path, "id", 1);
	if (field2 === void 0) throw missingField(path, "uid", 2);
	if (field3 === void 0) throw missingField(path, "kind", 3);
	if (field9 === void 0) throw missingField(path, "deleted", 9);
	if (field10 === void 0) throw missingField(path, "created_at", 10);
	if (field11 === void 0) throw missingField(path, "updated_at", 11);
	const result = {
		id: field1,
		uid: field2,
		kind: field3,
		title: field4,
		source_text: field5,
		file: field6,
		tags: field7,
		embedding: field8,
		deleted: field9,
		created_at: field10,
		updated_at: field11
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
var KNOWN_MemoryVersion = /* @__PURE__ */ new Set([
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
	12
]);
var RETIRED_MemoryVersion = /* @__PURE__ */ new Set([]);
function encodeMemoryVersion(value) {
	const writer = new Writer();
	writeMemoryVersion(writer, value, "MemoryVersion");
	return writer.finish();
}
function writeMemoryVersion(w, value, path) {
	const unknown = prepareUnknown(value.$unknown, KNOWN_MemoryVersion, path);
	let pending = 0;
	pending = flushUnknownBefore(w, unknown, pending, 1);
	w.key(1, 2);
	w.lengthDelimited(uuidToBytes(value.id, path + ".id"));
	pending = flushUnknownBefore(w, unknown, pending, 2);
	w.key(2, 2);
	w.lengthDelimited(uuidToBytes(value.memory_id, path + ".memory_id"));
	pending = flushUnknownBefore(w, unknown, pending, 3);
	w.key(3, 2);
	w.string(value.uid);
	pending = flushUnknownBefore(w, unknown, pending, 4);
	w.key(4, 2);
	w.string(value.kind);
	pending = flushUnknownBefore(w, unknown, pending, 5);
	if (value.title !== null && value.title !== void 0) {
		const present = value.title;
		w.key(5, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 6);
	if (value.source_text !== null && value.source_text !== void 0) {
		const present = value.source_text;
		w.key(6, 2);
		w.string(present);
	}
	pending = flushUnknownBefore(w, unknown, pending, 7);
	if (value.file !== null && value.file !== void 0) {
		const present = value.file;
		w.key(7, 2);
		w.lengthDelimited(uuidToBytes(present, path + ".file"));
	}
	pending = flushUnknownBefore(w, unknown, pending, 8);
	if (value.tags !== null && value.tags !== void 0) {
		const present = value.tags;
		w.key(8, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.string(item);
		}
		w.endNested(wrapperOffset);
	}
	pending = flushUnknownBefore(w, unknown, pending, 9);
	if (value.embedding !== null && value.embedding !== void 0) {
		const present = value.embedding;
		w.key(9, 2);
		{
			const nestedOffset = w.beginNested();
			writeEmbedding(w, present, path + ".embedding");
			w.endNested(nestedOffset);
		}
	}
	pending = flushUnknownBefore(w, unknown, pending, 10);
	w.key(10, 0);
	w.varintNumber(value.deleted ? 1 : 0);
	pending = flushUnknownBefore(w, unknown, pending, 11);
	w.key(11, 0);
	w.varintNumber(timestampToMillis(value.created_at, path + ".created_at"));
	pending = flushUnknownBefore(w, unknown, pending, 12);
	if (value.parent_ids !== null && value.parent_ids !== void 0) {
		const present = value.parent_ids;
		w.key(12, 2);
		const wrapperOffset = w.beginNested();
		for (const item of present) {
			w.key(1, 2);
			w.lengthDelimited(uuidToBytes(item, path + ".parent_ids"));
		}
		w.endNested(wrapperOffset);
	}
	flushUnknownRest(w, unknown, pending);
}
function decodeMemoryVersion(bytes) {
	return readMemoryVersion(Reader.of(bytes, "MemoryVersion"), "MemoryVersion");
}
function readMemoryVersion(r, path) {
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
				field2 = bytesToUuid(readBytesField(r, wire, path + ".memory_id"), path + ".memory_id");
				break;
			case 3:
				field3 = readStringField(r, wire, path + ".uid");
				break;
			case 4:
				field4 = readStringField(r, wire, path + ".kind");
				break;
			case 5:
				field5 = readStringField(r, wire, path + ".title");
				break;
			case 6:
				field6 = readStringField(r, wire, path + ".source_text");
				break;
			case 7:
				field7 = bytesToUuid(readBytesField(r, wire, path + ".file"), path + ".file");
				break;
			case 8: {
				expectWire(wire, 2, path + ".tags");
				const wrapper = r.subMessage(path + ".tags");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(readStringField(wrapper, innerWire, path + ".tags"));
				}
				field8 = items;
				break;
			}
			case 9:
				field9 = readEmbedding((expectWire(wire, 2, path + ".embedding"), r.subMessage(path + ".embedding")), path + ".embedding");
				break;
			case 10:
				field10 = readUnsignedField(r, wire, path + ".deleted") !== 0;
				break;
			case 11:
				field11 = millisToTimestamp(readSignedField(r, wire, path + ".created_at"), path + ".created_at");
				break;
			case 12: {
				expectWire(wire, 2, path + ".parent_ids");
				const wrapper = r.subMessage(path + ".parent_ids");
				const items = [];
				while (wrapper.hasMore()) {
					const innerKey = wrapper.key();
					const innerWire = innerKey & 7;
					if (innerKey >>> 3 !== 1) {
						wrapper.skipBody(innerWire);
						continue;
					}
					items.push(bytesToUuid(readBytesField(wrapper, innerWire, path + ".parent_ids"), path + ".parent_ids"));
				}
				field12 = items;
				break;
			}
			default: unknown = captureUnknown(r, wireKey, tag, wire, unknown, RETIRED_MemoryVersion);
		}
	}
	if (field1 === void 0) throw missingField(path, "id", 1);
	if (field2 === void 0) throw missingField(path, "memory_id", 2);
	if (field3 === void 0) throw missingField(path, "uid", 3);
	if (field4 === void 0) throw missingField(path, "kind", 4);
	if (field10 === void 0) throw missingField(path, "deleted", 10);
	if (field11 === void 0) throw missingField(path, "created_at", 11);
	const result = {
		id: field1,
		memory_id: field2,
		uid: field3,
		kind: field4,
		title: field5,
		source_text: field6,
		file: field7,
		tags: field8,
		embedding: field9,
		deleted: field10,
		created_at: field11,
		parent_ids: field12
	};
	if (unknown !== void 0 && unknown.length > 0) result.$unknown = unknown;
	return result;
}
//#endregion
//#region src/vault/collections/memories.ts
function mintUid() {
	return crypto.randomUUID();
}
var fields = {
	kind: {
		kind: "string",
		get: (row) => row.kind
	},
	title: {
		kind: "string",
		get: (row) => row.title
	},
	source_text: {
		kind: "string",
		get: (row) => row.source_text
	},
	tags: {
		kind: "stringList",
		get: (row) => row.tags
	},
	deleted: {
		kind: "bool",
		get: (row) => row.deleted
	},
	created_at: {
		kind: "date",
		get: (row) => row.created_at
	},
	updated_at: {
		kind: "date",
		get: (row) => row.updated_at
	}
};
/**
* Cosine similarity between two normalized vectors, which is their dot product.
* Vectors from different models never compare — a mismatch means the memory
* needs re-embedding, not a smaller score.
*/
function cosineSimilarity(left, right) {
	if (left.length !== right.length) return 0;
	let total = 0;
	for (let i = 0; i < left.length; i++) total += left[i] * right[i];
	return total;
}
var memoriesCollection = {
	name: "memories",
	encodeRow: encodeMemory,
	decodeRow: decodeMemory,
	encodeVersion: encodeMemoryVersion,
	decodeVersion: decodeMemoryVersion,
	prepare(input, existing, id, now) {
		return {
			kind: "text",
			deleted: false,
			...input,
			id,
			uid: input.uid || existing?.uid || mintUid(),
			created_at: input.created_at || existing?.created_at || now,
			updated_at: now
		};
	},
	versionOf(versionId, row, parentIds, createdAt) {
		const { id, created_at, updated_at, $unknown, ...rest } = row;
		return {
			...rest,
			id: versionId,
			memory_id: id,
			created_at: createdAt,
			parent_ids: parentIds.length > 0 ? parentIds : void 0
		};
	},
	rowFieldsOf(version) {
		const { id, memory_id, created_at, parent_ids, $unknown, ...rest } = version;
		return rest;
	},
	merge: lastWriterWins,
	fields,
	searchText: (row) => [
		row.title ?? "",
		row.source_text ?? "",
		...list(row.tags)
	],
	matchesScope(row, scope) {
		if (scope === "ALL") return true;
		if (scope === "TRASHED") return row.deleted;
		return !row.deleted;
	},
	comparators: {
		CREATED_AT: (a, b) => compareDates(a.created_at, b.created_at),
		UPDATED_AT: (a, b) => compareDates(a.updated_at, b.updated_at),
		TITLE: (a, b) => compareText(a.title, b.title),
		RELEVANCE: () => 0
	},
	defaultSort: [{
		field: "UPDATED_AT",
		direction: "DESC"
	}],
	/**
	* Semantic ordering when the caller supplied a query vector. Rows whose
	* embedding is missing or from another model keep their lexical position at
	* the end rather than dropping out, so recall never depends on the embedder
	* having caught up.
	*/
	rank(rows, options) {
		const query = options.queryVector;
		if (!query) return null;
		const scored = rows.map((row) => {
			const embedding = row.embedding;
			if (!embedding || embedding.model !== query.model) return {
				row,
				score: -1
			};
			return {
				row,
				score: cosineSimilarity(embedding.vector, query.vector)
			};
		});
		scored.sort((left, right) => right.score - left.score);
		return scored.map((entry) => entry.row);
	}
};
//#endregion
//#region src/vault/collections/index.ts
var REGISTRY = /* @__PURE__ */ new Map([
	[contactsCollection.name, contactsCollection],
	[calendarCollection.name, calendarCollection],
	[memoriesCollection.name, memoriesCollection]
]);
function collectionSpec(name) {
	return REGISTRY.get(name) ?? null;
}
function collectionNames() {
	return [...REGISTRY.keys()];
}
//#endregion
//#region src/vault/protocol.ts
var OP_VERBS = [
	"start",
	"stop",
	"sync",
	"list",
	"count",
	"get",
	"write",
	"trash",
	"history",
	"restore-version"
];
/** Verbs that mutate data, and so need a write-implying grant. */
var WRITE_VERBS = /* @__PURE__ */ new Set([
	"write",
	"trash",
	"restore-version"
]);
/** Splits `calendar-restore-version` into its collection and verb. */
function parseOp(type) {
	const separator = type.indexOf("-");
	if (separator <= 0) return null;
	const collection = type.slice(0, separator);
	const verb = type.slice(separator + 1);
	if (!OP_VERBS.includes(verb)) return null;
	return {
		collection,
		verb
	};
}
/**
* Start and sync stay read ops — pulling is reading, and a read-only client must
* still be able to refresh what it is allowed to see.
*/
function opNeedsWrite(verb) {
	return WRITE_VERBS.has(verb);
}
//#endregion
//#region src/vault/host.ts
function createVaultStore(options) {
	const api = new ApiClient({
		apiUrl: options.apiUrl,
		getToken: options.getToken,
		refreshToken: options.refreshToken
	});
	const engines = /* @__PURE__ */ new Map();
	const starting = /* @__PURE__ */ new Map();
	function engineFor(spec) {
		const existing = engines.get(spec.name);
		if (existing) return existing;
		const engine = new CollectionEngine({
			collection: spec,
			spaces: new VaultSpaces(api, options.crypto, spec.name, options.ownUserId),
			sync: new VaultSync(api),
			crypto: options.crypto,
			ownUserId: options.ownUserId
		});
		engine.on("changed", () => options.emit(spec.name, "changed"));
		engine.on("progress", (detail) => options.emit(spec.name, "progress", detail));
		engine.on("error", (detail) => options.emit(spec.name, "error", detail));
		engines.set(spec.name, engine);
		return engine;
	}
	function start(engine, collection, pollIntervalMs) {
		const inFlight = starting.get(collection);
		if (inFlight) return inFlight;
		const pass = engine.start(pollIntervalMs).catch((error) => {
			starting.delete(collection);
			throw error;
		});
		starting.set(collection, pass);
		return pass;
	}
	async function handle(message) {
		const op = parseOp(String(message.type));
		if (!op) throw new Error(`unknown op: ${String(message.type)}`);
		const spec = collectionSpec(op.collection);
		if (!spec) throw new Error(`unknown collection: ${op.collection}`);
		const engine = engineFor(spec);
		switch (op.verb) {
			case "start": {
				const pollIntervalMs = typeof message.pollIntervalMs === "number" ? message.pollIntervalMs : 3e4;
				await start(engine, op.collection, pollIntervalMs);
				return { started: true };
			}
			case "stop":
				engine.stop();
				starting.delete(op.collection);
				return { stopped: true };
			case "sync":
				await engine.syncOnce();
				return { synced: true };
			case "list": {
				const result = await engine.list(queryOf(message));
				return {
					items: result.items,
					total: result.total
				};
			}
			case "count": return { count: await engine.count(queryOf(message)) };
			case "get": return { item: await engine.get(String(message.id)) };
			case "write": {
				const spaceId = typeof message.spaceId === "string" ? message.spaceId : void 0;
				return { id: await engine.write(message.row, spaceId) };
			}
			case "trash":
				await engine.trash(String(message.id));
				return { trashed: true };
			case "history": return { versions: await engine.history(String(message.id)) };
			case "restore-version":
				await engine.restoreVersion(String(message.id), String(message.versionId));
				return { restored: true };
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
//#region src/vault/index.ts
if (typeof window !== "undefined") {
	window.__createVaultStore = createVaultStore;
	window.__collectionNames = collectionNames;
	window.__opNeedsWrite = opNeedsWrite;
	window.__parseOp = parseOp;
}
//#endregion
export { collectionNames, createVaultStore, opNeedsWrite, parseOp };

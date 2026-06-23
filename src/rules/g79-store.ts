import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const NETEASE_INIT_URL = "http://optsdk.gameyw.netease.com";
const G79_DECRYPT_KEY = "c42bf7f39d476db3";
const REFRESH_INTERVAL_MS = 30 * 60 * 1000;
const PREVIOUS_SNAPSHOT_RETENTION_MS = 3 * 60 * 1000;
const DEFAULT_CACHE_FILE = join(process.cwd(), ".cache", "g79-rules.json");

type RuleMap = Record<string, string>;
type RegexGroups = Record<string, RuleMap>;

export type G79RuleSet = {
  regex: RegexGroups;
  [key: string]: unknown;
};

type CacheFile = {
  updatedAt: string;
  sourceUrl: string;
  hash: string;
  rules: G79RuleSet;
};

export type G79StoreStatus = {
  snapshotMode: "active" | "previous-fallback" | "unavailable";
  loadedFromCache: boolean;
  hasRules: boolean;
  hash: string | null;
  compiledAt: number | null;
  sourceUrl: string | null;
  updatedAt: number | null;
  lastAttemptAt: number | null;
  lastError: string | null;
  refreshIntervalMs: number;
  categoryCount: number;
  previousSnapshot: {
    retained: boolean;
    hash: string | null;
    expiresAt: number | null;
  };
};

type Snapshot = {
  updatedAt: string;
  sourceUrl: string;
  hash: string;
  rules: G79RuleSet;
};

type RuntimeSnapshot = Snapshot & {
  compiledAt: string;
  compiledGroups: Record<string, CompiledRule[]>;
  summaries: RuleGroupSummary[];
};

type CompiledRule = {
  id: string;
  displayId: string;
  source: string;
  regex: RegExp | null;
  error: string | null;
};

type RuleGroupSummary = {
  name: string;
  patternCount: number;
  compiledPatternCount: number;
  invalidPatternCount: number;
};

type MatchRange = {
  value: string;
  start: number;
  end: number;
};

type TextProjection = {
  rawText: string;
  checkedText: string;
  hasMinecraftFormatting: boolean;
};

export type G79RuleHit = {
  rule: string;
  id: string;
  displayId: string;
  pattern: string;
  violations: string[];
  ranges: MatchRange[];
  replacedText: string;
};

export type G79CheckResult = {
  text: string;
  requestedRules: string[];
  resolvedRules: string[];
  unknownRules: string[];
  mode: "first-match" | "all-results";
  matched: boolean;
  checkedGroupCount: number;
  checkedPatternCount: number;
  invalidPatternCount: number;
  violationWords: string[];
  replacedText: string;
  firstHit: G79RuleHit | null;
  hitCount: number;
  hits?: G79RuleHit[];
};

export type G79CheckMode = "all" | "first";

export class G79RuleStore {
  private readonly cachePath: string;
  private readonly refreshIntervalMs: number;
  private activeSnapshot: RuntimeSnapshot | null = null;
  private previousSnapshot: RuntimeSnapshot | null = null;
  private previousSnapshotExpiresAt: string | null = null;
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private previousSnapshotCleanupTimer: ReturnType<typeof setTimeout> | null = null;
  private refreshPromise: Promise<RuntimeSnapshot> | null = null;
  private loadedFromCache = false;
  private lastAttemptAt: string | null = null;
  private lastError: string | null = null;

  constructor(options?: { cachePath?: string; refreshIntervalMs?: number }) {
    this.cachePath = options?.cachePath ?? DEFAULT_CACHE_FILE;
    this.refreshIntervalMs = options?.refreshIntervalMs ?? REFRESH_INTERVAL_MS;
  }

  async initialize() {
    await this.loadCacheIfPresent();

    if (this.activeSnapshot) {
      console.log(`Loaded g79 rules from cache: ${this.cachePath}`);
      void this.refresh("startup");
    } else {
      await this.refresh("startup");
    }

    this.refreshTimer = setInterval(() => {
      void this.refresh("interval");
    }, this.refreshIntervalMs);
  }

  getRules() {
    return this.getReadableSnapshot()?.rules ?? null;
  }

  getAvailableRuleNames() {
    return Object.keys(this.getReadableSnapshot()?.compiledGroups ?? {}).sort((left, right) =>
      left.localeCompare(right),
    );
  }

  getRuleSummaries(): RuleGroupSummary[] {
    return this.getReadableSnapshot()?.summaries ?? [];
  }

  checkText(
    text: string,
    requestedRules: string[],
    options?: { mode?: G79CheckMode; preserveFormatting?: boolean },
  ) {
    const runtimeSnapshot = this.getReadableSnapshot();

    if (!runtimeSnapshot) {
      throw new Error("g79 rules are not loaded yet.");
    }

    const requested = normalizeRequestedRules(requestedRules);
    const resolved = this.resolveRuleNames(runtimeSnapshot, requested);
    const mode = options?.mode ?? "all";
    const stopAtFirstHit = mode === "first";
    const preserveFormatting = options?.preserveFormatting ?? false;
    const projection = preserveFormatting ? projectTextForCheck(text) : {
      rawText: text,
      checkedText: text,
      hasMinecraftFormatting: false,
    };
    const hits: G79RuleHit[] = [];
    const allRanges: MatchRange[] = [];
    const violationWords: string[] = [];
    let checkedGroupCount = 0;
    let checkedPatternCount = 0;
    let invalidPatternCount = 0;

    for (const ruleName of resolved.resolvedRules) {
      checkedGroupCount += 1;
      const group = runtimeSnapshot.compiledGroups[ruleName] ?? [];

      for (const entry of group) {
        if (!entry.regex) {
          invalidPatternCount += 1;
          continue;
        }

        checkedPatternCount += 1;
        const ranges = collectMatchRanges(entry.regex, projection.checkedText);

        if (ranges.length === 0) {
          continue;
        }

        const hit = {
          rule: ruleName,
          id: entry.id,
          displayId: entry.displayId,
          pattern: entry.source,
          violations: uniqueValues(ranges.map((range) => range.value)),
          ranges,
          replacedText: maskProjectedText(projection, ranges),
        } satisfies G79RuleHit;

        hits.push(hit);
        appendUnique(violationWords, hit.violations);
        allRanges.push(...ranges);

        if (stopAtFirstHit) {
          return {
            text,
            requestedRules: requested,
            resolvedRules: resolved.resolvedRules,
            unknownRules: resolved.unknownRules,
            mode: "first-match",
            matched: true,
            checkedGroupCount,
            checkedPatternCount,
            invalidPatternCount,
            violationWords: hit.violations,
            replacedText: hit.replacedText,
            firstHit: hit,
            hitCount: 1,
          } satisfies G79CheckResult;
        }
      }
    }

    const replacedText = allRanges.length > 0 ? maskProjectedText(projection, allRanges) : text;
    const firstHit = hits[0] ?? null;

    return {
      text,
      requestedRules: requested,
      resolvedRules: resolved.resolvedRules,
      unknownRules: resolved.unknownRules,
      mode: stopAtFirstHit ? "first-match" : "all-results",
      matched: hits.length > 0,
      checkedGroupCount,
      checkedPatternCount,
      invalidPatternCount,
      violationWords: firstHit ? violationWords : [],
      replacedText,
      firstHit,
      hitCount: hits.length,
      ...(!stopAtFirstHit ? { hits } : {}),
    } satisfies G79CheckResult;
  }

  getStatus(): G79StoreStatus {
    const runtimeSnapshot = this.getReadableSnapshot();
    const snapshotMode = this.activeSnapshot
      ? "active"
      : runtimeSnapshot
        ? "previous-fallback"
        : "unavailable";

    return {
      snapshotMode,
      loadedFromCache: this.loadedFromCache,
      hasRules: runtimeSnapshot !== null,
      hash: runtimeSnapshot?.hash ?? null,
      compiledAt: toUnixSeconds(runtimeSnapshot?.compiledAt ?? null),
      sourceUrl: runtimeSnapshot?.sourceUrl ?? null,
      updatedAt: toUnixSeconds(runtimeSnapshot?.updatedAt ?? null),
      lastAttemptAt: toUnixSeconds(this.lastAttemptAt),
      lastError: this.lastError,
      refreshIntervalMs: this.refreshIntervalMs,
      categoryCount: Object.keys(runtimeSnapshot?.rules.regex ?? {}).length,
      previousSnapshot: {
        retained: this.previousSnapshot !== null,
        hash: this.previousSnapshot?.hash ?? null,
        expiresAt: toUnixSeconds(this.previousSnapshotExpiresAt),
      },
    };
  }

  async refresh(reason: "startup" | "interval" | "manual") {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = this.performRefresh(reason).finally(() => {
      this.refreshPromise = null;
    });

    return this.refreshPromise;
  }

  dispose() {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }

    if (this.previousSnapshotCleanupTimer) {
      clearTimeout(this.previousSnapshotCleanupTimer);
      this.previousSnapshotCleanupTimer = null;
    }
  }

  private async loadCacheIfPresent() {
    try {
      const raw = await readFile(this.cachePath, "utf8");
      const parsed = JSON.parse(raw) as CacheFile;

      if (!parsed?.rules?.regex) {
        throw new Error("Cache file format is invalid.");
      }

      this.activeSnapshot = this.createRuntimeSnapshot({
        updatedAt: parsed.updatedAt,
        sourceUrl: parsed.sourceUrl,
        hash: parsed.hash,
        rules: parsed.rules,
      });
      this.clearPreviousSnapshot();
      this.loadedFromCache = true;
      this.lastError = null;
    } catch (error) {
      if (getErrorCode(error) === "ENOENT") {
        return;
      }

      const message = error instanceof Error ? error.message : String(error);
      this.lastError = `Failed to load cache: ${message}`;
      console.warn(this.lastError);
    }
  }

  private async performRefresh(reason: "startup" | "interval" | "manual") {
    this.lastAttemptAt = new Date().toISOString();

    try {
      const sourceUrl = await resolveG79DownloadUrl();

      // 拉到的下载地址与当前快照一致，本轮跳过更新，避免重复下载和解密。
      const currentSnapshot = this.activeSnapshot;
      if (currentSnapshot && currentSnapshot.sourceUrl === sourceUrl) {
        console.log(`[g79] Skipped refresh (${reason}): sourceUrl unchanged`);
        return currentSnapshot;
      }

      const rules = await fetchAndDecryptG79Rules(sourceUrl);
      const nextSnapshot = this.createRuntimeSnapshot({
        updatedAt: new Date().toISOString(),
        sourceUrl,
        hash: stableHash(rules),
        rules,
      });

      this.promoteSnapshot(nextSnapshot, { loadedFromCache: false });
      await persistCache(this.cachePath, nextSnapshot);

      console.log(`[g79] Refreshed rules (${reason}) hash=${nextSnapshot.hash}`);
      return nextSnapshot;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.lastError = `Failed to refresh g79 rules: ${message}`;
      console.warn(`[g79] ${this.lastError}`);

      if (this.activeSnapshot) {
        return this.activeSnapshot;
      }

      if (this.previousSnapshot) {
        return this.previousSnapshot;
      }

      throw error;
    }
  }

  private resolveRuleNames(runtimeSnapshot: RuntimeSnapshot, requestedRules: string[]) {
    const availableRules = Object.keys(runtimeSnapshot.compiledGroups).sort((left, right) =>
      left.localeCompare(right),
    );
    const ruleNameLookup = new Map(
      availableRules.map((ruleName) => [ruleName.toLowerCase(), ruleName]),
    );

    if (requestedRules.includes("all")) {
      return {
        resolvedRules: availableRules,
        unknownRules: [] as string[],
      };
    }

    const resolvedRules: string[] = [];
    const unknownRules: string[] = [];

    for (const requestedRule of requestedRules) {
      const resolvedRule = ruleNameLookup.get(requestedRule.toLowerCase());

      if (!resolvedRule) {
        unknownRules.push(requestedRule);
        continue;
      }

      if (!resolvedRules.includes(resolvedRule)) {
        resolvedRules.push(resolvedRule);
      }
    }

    return {
      resolvedRules,
      unknownRules,
    };
  }

  private getReadableSnapshot() {
    if (this.activeSnapshot) {
      return this.activeSnapshot;
    }

    if (!this.previousSnapshot || !this.previousSnapshotExpiresAt) {
      return null;
    }

    if (Date.now() > Date.parse(this.previousSnapshotExpiresAt)) {
      this.clearPreviousSnapshot();
      return null;
    }

    return this.previousSnapshot;
  }

  private createRuntimeSnapshot(snapshot: Snapshot): RuntimeSnapshot {
    const compiledGroups = compileRegexGroups(snapshot.rules.regex);

    return {
      ...snapshot,
      compiledAt: new Date().toISOString(),
      compiledGroups,
      summaries: buildRuleGroupSummaries(compiledGroups),
    };
  }

  private promoteSnapshot(nextSnapshot: RuntimeSnapshot, options: { loadedFromCache: boolean }) {
    const currentSnapshot = this.activeSnapshot;

    this.activeSnapshot = nextSnapshot;
    this.loadedFromCache = options.loadedFromCache;
    this.lastError = null;

    if (currentSnapshot) {
      this.retainPreviousSnapshot(currentSnapshot);
    }
  }

  private retainPreviousSnapshot(snapshot: RuntimeSnapshot) {
    if (this.previousSnapshotCleanupTimer) {
      clearTimeout(this.previousSnapshotCleanupTimer);
      this.previousSnapshotCleanupTimer = null;
    }

    const expiresAt = new Date(Date.now() + PREVIOUS_SNAPSHOT_RETENTION_MS);
    this.previousSnapshot = snapshot;
    this.previousSnapshotExpiresAt = expiresAt.toISOString();
    this.previousSnapshotCleanupTimer = setTimeout(() => {
      if (this.previousSnapshot === snapshot) {
        this.clearPreviousSnapshot();
      }
    }, PREVIOUS_SNAPSHOT_RETENTION_MS);

    this.previousSnapshotCleanupTimer.unref?.();
  }

  private clearPreviousSnapshot() {
    if (this.previousSnapshotCleanupTimer) {
      clearTimeout(this.previousSnapshotCleanupTimer);
      this.previousSnapshotCleanupTimer = null;
    }

    this.previousSnapshot = null;
    this.previousSnapshotExpiresAt = null;
  }
}

async function persistCache(cachePath: string, snapshot: Snapshot) {
  await mkdir(dirname(cachePath), { recursive: true });

  const cacheFile: CacheFile = {
    updatedAt: snapshot.updatedAt,
    sourceUrl: snapshot.sourceUrl,
    hash: snapshot.hash,
    rules: snapshot.rules,
  };

  await writeFile(cachePath, JSON.stringify(cacheFile, null, 2), "utf8");
}

async function resolveG79DownloadUrl() {
  const attempts = [
    { endpointGameId: "android_g79", payloadGameId: "android_g79" },
    { endpointGameId: "android_g79", payloadGameId: "g79" },
  ];

  let lastError: Error | null = null;

  for (const attempt of attempts) {
    try {
      return await requestDownloadUrl(attempt.endpointGameId, attempt.payloadGameId);
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
    }
  }

  throw lastError ?? new Error("Could not resolve g79 download URL.");
}

async function requestDownloadUrl(endpointGameId: string, payloadGameId: string) {
  const payload = {
    version: "3.7.15.287970",
    sys: "android",
    deviceid: "865f7d278a212e94",
    network: "wifi",
    info: {},
    gameid: payloadGameId,
  };

  const encodedPayload = Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
  const response = await fetch(`${NETEASE_INIT_URL}/initbox_${endpointGameId}.html`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: encodedPayload,
  });

  if (!response.ok) {
    throw new Error(`Init request failed with status ${response.status}.`);
  }

  const data = (await response.json()) as { url_one?: unknown; url?: unknown };
  const downloadUrl = (typeof data.url_one === "string" && data.url_one.length > 0)
    ? data.url_one
    : data.url;

  if (typeof downloadUrl !== "string" || downloadUrl.length === 0) {
    throw new Error("Init response did not contain a usable url.");
  }

  return downloadUrl;
}

async function fetchAndDecryptG79Rules(sourceUrl: string) {
  const response = await fetch(sourceUrl);

  if (!response.ok) {
    throw new Error(`Rule download failed with status ${response.status}.`);
  }

  const encryptedBase64 = await response.text();
  const encryptedBytes = Uint8Array.from(Buffer.from(encryptedBase64.trim(), "base64"));
  const decryptedBytes = rc4(encryptedBytes, Buffer.from(G79_DECRYPT_KEY, "utf8"));
  const decryptedText = new TextDecoder().decode(decryptedBytes);
  const parsed = JSON.parse(decryptedText) as G79RuleSet;

  return decodePcreUnicodeInObject(parsed);
}

function rc4(data: Uint8Array, key: Uint8Array) {
  const s = new Uint8Array(256);

  for (let index = 0; index < 256; index += 1) {
    s[index] = index;
  }

  let j = 0;
  for (let index = 0; index < 256; index += 1) {
    j = (j + s[index] + key[index % key.length]) & 0xff;
    [s[index], s[j]] = [s[j], s[index]];
  }

  const output = new Uint8Array(data.length);
  let i = 0;
  j = 0;

  for (let index = 0; index < data.length; index += 1) {
    i = (i + 1) & 0xff;
    j = (j + s[i]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
    const k = s[(s[i] + s[j]) & 0xff];
    output[index] = data[index] ^ k;
  }

  return output;
}

function isChineseUnicode(codePoint: number): boolean {
  // CJK Unified Ideographs Extension A: U+3400 - U+4DBF
  // CJK Unified Ideographs: U+4E00 - U+9FFF
  return codePoint >= 0x3400 && codePoint <= 0x9fff;
}

function decodePcreUnicodeInObject(value: unknown): any {
  if (Array.isArray(value)) {
    return value.map((item) => decodePcreUnicodeInObject(item));
  }

  if (value && typeof value === "object") {
    const entries = Object.entries(value).map(([key, nestedValue]) => [
      key,
      decodePcreUnicodeInObject(nestedValue),
    ]);

    return Object.fromEntries(entries);
  }

  if (typeof value === "string") {
    return value.replace(/\\x\{([0-9a-fA-F]+)\}/g, (_, hex) => {
      let codePoint = Number.parseInt(hex, 16);
      // 中文 Unicode 需要 -1
      if (isChineseUnicode(codePoint)) {
        codePoint -= 1;
      }
      return String.fromCodePoint(codePoint);
    });
  }

  return value;
}

function stableHash(value: unknown) {
  const normalized = JSON.stringify(sortValue(value));
  return createHash("sha256").update(normalized).digest("hex");
}

function normalizeRequestedRules(requestedRules: string[]) {
  const normalized: string[] = [];

  for (const ruleName of requestedRules) {
    const trimmed = ruleName.trim();

    if (!trimmed) {
      continue;
    }

    if (!normalized.includes(trimmed)) {
      normalized.push(trimmed);
    }
  }

  return normalized;
}

function appendUnique(target: string[], values: string[]) {
  for (const value of values) {
    if (!target.includes(value)) {
      target.push(value);
    }
  }
}

function collectMatchRanges(regex: RegExp, text: string) {
  const ranges: MatchRange[] = [];
  regex.lastIndex = 0;

  try {
    while (true) {
      const match = regex.exec(text);

      if (!match) {
        break;
      }

      const value = match[0] ?? "";
      const start = match.index ?? -1;

      if (!value || start < 0) {
        if (value.length === 0) {
          regex.lastIndex += 1;
        }
        continue;
      }

      ranges.push({
        value,
        start,
        end: start + value.length,
      });

      if (value.length === 0) {
        regex.lastIndex += 1;
      }
    }
  } finally {
    regex.lastIndex = 0;
  }

  return ranges;
}

function projectTextForCheck(text: string): TextProjection {
  let checkedText = "";
  let hasMinecraftFormatting = false;

  for (let index = 0; index < text.length; index += 1) {
    const current = text[index];

    if (current === "§" && index + 1 < text.length) {
      hasMinecraftFormatting = true;
      index += 1;
      continue;
    }

    checkedText += current;
  }

  return {
    rawText: text,
    checkedText,
    hasMinecraftFormatting,
  };
}

function maskProjectedText(projection: TextProjection, ranges: MatchRange[]) {
  if (!projection.hasMinecraftFormatting) {
    return maskText(projection.rawText, ranges);
  }

  const mergedRanges = mergeRanges(ranges);

  if (mergedRanges.length === 0) {
    return projection.rawText;
  }

  let result = "";
  let visibleIndex = 0;
  let rangeIndex = 0;

  for (let rawIndex = 0; rawIndex < projection.rawText.length; rawIndex += 1) {
    const current = projection.rawText[rawIndex];

    if (current === "§" && rawIndex + 1 < projection.rawText.length) {
      result += current;
      result += projection.rawText[rawIndex + 1];
      rawIndex += 1;
      continue;
    }

    while (rangeIndex < mergedRanges.length && visibleIndex >= mergedRanges[rangeIndex].end) {
      rangeIndex += 1;
    }

    const currentRange = mergedRanges[rangeIndex];
    const inRange =
      currentRange !== undefined &&
      visibleIndex >= currentRange.start &&
      visibleIndex < currentRange.end;

    result += inRange ? "*" : current;
    visibleIndex += 1;
  }

  return result;
}

function maskText(text: string, ranges: MatchRange[]) {
  if (ranges.length === 0) {
    return text;
  }

  const masked = [...text];
  const mergedRanges = mergeRanges(ranges);

  for (const range of mergedRanges) {
    for (let index = range.start; index < range.end && index < masked.length; index += 1) {
      masked[index] = "*";
    }
  }

  return masked.join("");
}

function mergeRanges(ranges: MatchRange[]) {
  const sorted = [...ranges].sort((left, right) => left.start - right.start);
  const merged: MatchRange[] = [];

  for (const current of sorted) {
    const previous = merged[merged.length - 1];

    if (!previous || current.start > previous.end) {
      merged.push({ ...current });
      continue;
    }

    previous.end = Math.max(previous.end, current.end);
  }

  return merged;
}

function uniqueValues(values: string[]) {
  return [...new Set(values)];
}

function compileRegexGroups(groups: RegexGroups) {
  return Object.fromEntries(
    Object.entries(groups).map(([groupName, patterns]) => [
      groupName,
      Object.entries(patterns).map(([id, source]) => compileRule(groupName, id, source)),
    ]),
  );
}

function buildRuleGroupSummaries(compiledGroups: Record<string, CompiledRule[]>) {
  return Object.keys(compiledGroups)
    .sort((left, right) => left.localeCompare(right))
    .map((name) => {
      const group = compiledGroups[name] ?? [];
      const compiledPatternCount = group.filter((entry) => entry.regex !== null).length;

      return {
        name,
        patternCount: group.length,
        compiledPatternCount,
        invalidPatternCount: group.length - compiledPatternCount,
      };
    });
}

function compileRule(groupName: string, id: string, source: string): CompiledRule {
  try {
    const compiled = createRuntimeRegex(source);

    return {
      id,
      displayId: `${groupName}-${id}`,
      source,
      regex: compiled,
      error: null,
    };
  } catch (error) {
    return {
      id,
      displayId: `${groupName}-${id}`,
      source,
      regex: null,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function createRuntimeRegex(source: string) {
  const extracted = extractLeadingFlags(source);
  const flags = extracted.flags.includes("g") ? extracted.flags : `${extracted.flags}g`;
  return new RegExp(extracted.pattern, flags);
}

function extractLeadingFlags(source: string) {
  let pattern = source;
  const flags = new Set<string>();

  while (true) {
    const match = pattern.match(/^\(\?([A-Za-z]+)\)/);
    if (!match) {
      break;
    }

    for (const flag of match[1]) {
      if ("imsu".includes(flag)) {
        flags.add(flag);
      }
    }

    pattern = pattern.slice(match[0].length);
  }

  return {
    pattern,
    flags: [...flags].join(""),
  };
}

function getErrorCode(error: unknown) {
  if (!error || typeof error !== "object" || !("code" in error)) {
    return null;
  }

  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : null;
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => sortValue(item));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nestedValue]) => [key, sortValue(nestedValue)]),
    );
  }

  return value;
}

function toUnixSeconds(value: string | null) {
  if (!value) {
    return null;
  }

  const timestamp = Date.parse(value);
  return Number.isNaN(timestamp) ? null : Math.floor(timestamp / 1000);
}

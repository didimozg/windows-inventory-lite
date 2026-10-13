// Node-only tests for the pure, logic-bearing functions server/dashboard/app.js
// exports purely for this file (see the module.exports guard at the very end
// of app.js - inert in a real browser, since `module` is never defined there).
//
// app.js has no module system to split these functions into their own file
// without touching every call site in a ~7.5k-line IIFE, and this project has
// no bundler/npm dependency to pull in a real DOM (jsdom etc.) - adding one
// would be the first external dependency this dashboard has ever had. Instead,
// requiring app.js here runs its entire top-level bootstrap (hundreds of
// `byId(...).addEventListener(...)` calls, an initial fetch, etc.) against the
// minimal stub `document`/`window`/`fetch` below: a single Proxy-based stub
// element absorbs any method call or property access as a harmless no-op, so
// the bootstrap completes without throwing, without needing to enumerate
// every DOM API it happens to touch. The stub is deliberately generic rather
// than a real DOM: this file does not test the bootstrap itself, only the
// pure functions app.js chooses to export afterward.
//
// Run directly: node tests/dashboard-logic.test.js
// Exit code 0 = all passed, 1 = at least one failure (same convention this
// project's C# --self-test already uses).

'use strict';

// Every stub element is itself callable (so `byId(x).addEventListener(...)`
// works) AND chainable (so `byId(x).classList.toggle(...)` also works,
// since `classList` lazily resolves to another full stub element, not a
// plain function) - one generic shape absorbs any DOM method/property the
// bootstrap happens to touch without needing to enumerate them.
function createStubElement() {
  const callable = function () { return createStubElement(); };
  return new Proxy(callable, {
    get(target, prop) {
      if (prop === 'then') return undefined; // keeps `await stub` / Promise-detection code from misbehaving
      if (!(prop in target)) {
        target[prop] = createStubElement();
      }
      return target[prop];
    },
    set(target, prop, value) {
      target[prop] = value;
      return true;
    },
  });
}

const stubDocument = {
  getElementById: () => createStubElement(),
  querySelector: () => createStubElement(),
  querySelectorAll: () => [],
  addEventListener: () => {},
  createElement: () => createStubElement(),
  documentElement: createStubElement(),
  body: createStubElement(),
  visibilityState: 'hidden',
};

global.document = stubDocument;
global.window = {
  setInterval: () => 0,
  clearInterval: () => {},
  setTimeout: (fn) => setTimeout(fn, 0),
  clearTimeout: () => {},
  addEventListener: () => {},
  location: { reload: () => {}, hash: '', href: 'http://localhost/' },
  matchMedia: () => ({ matches: false, addEventListener: () => {} }),
};
global.localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {},
};
// global.navigator is left alone - modern Node already defines its own
// read-only Navigator-like global, and app.js's bootstrap doesn't need
// anything more specific from it.
// Bootstrap fires an initial fetch('/api/v1/clients') - reject immediately
// and let its own .catch() (every real call site has one) absorb it rather
// than leaving an unhandled rejection or hanging the process.
global.fetch = () => Promise.reject(new Error('fetch is stubbed out in this Node test harness'));

const path = require('path');
const dashboard = require(path.join('..', 'server', 'dashboard', 'app.js'));

let passed = 0;
let failed = 0;

function check(description, fn) {
  try {
    const failure = fn();
    if (failure) {
      failed += 1;
      console.log('FAIL ' + description + ' - ' + failure);
    } else {
      passed += 1;
      console.log('PASS ' + description);
    }
  } catch (err) {
    failed += 1;
    console.log('FAIL ' + description + ' - threw: ' + err.message);
  }
}

check('escapeHtml escapes all five HTML-significant characters', () => {
  const result = dashboard.escapeHtml('<script>alert("x" & \'y\')</script>');
  const expected = '&lt;script&gt;alert(&quot;x&quot; &amp; &#39;y&#39;)&lt;/script&gt;';
  if (result !== expected) return 'expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(result);
});

check('escapeHtml renders null/undefined/empty as the literal text "Unknown"', () => {
  if (dashboard.escapeHtml(null) !== 'Unknown') return 'expected "Unknown" for null';
  if (dashboard.escapeHtml(undefined) !== 'Unknown') return 'expected "Unknown" for undefined';
  if (dashboard.escapeHtml('') !== 'Unknown') return 'expected "Unknown" for an empty string';
});

check('escapeHtml does not double-escape a value that merely contains the word "Unknown"', () => {
  if (dashboard.escapeHtml('Unknown') !== 'Unknown') return 'expected "Unknown" to pass through unchanged';
});

check('escapeHtmlOrEmpty renders null/undefined as empty, never the word "Unknown"', () => {
  if (dashboard.escapeHtmlOrEmpty(null) !== '') return 'expected empty string for null';
  if (dashboard.escapeHtmlOrEmpty(undefined) !== '') return 'expected empty string for undefined';
  if (dashboard.escapeHtmlOrEmpty('<b>') !== '&lt;b&gt;') return 'expected escaping to still apply to a real value';
});

check('text() renders null/undefined/empty as "Unknown", everything else via String()', () => {
  if (dashboard.text(null) !== 'Unknown') return 'expected "Unknown" for null';
  if (dashboard.text(0) !== '0') return 'expected "0" (a real, falsy-but-present value) not to become "Unknown"';
  if (dashboard.text(false) !== 'false') return 'expected "false" not to become "Unknown"';
});

check('isStale returns false whenever lastInstalledAtUtc is set, regardless of collectedAt age', () => {
  const longAgo = new Date(Date.now() - 1000 * 60 * 60 * 24 * 365).toISOString();
  if (dashboard.isStale({ lastInstalledAtUtc: '2020-01-01T00:00:00Z', collectedAt: longAgo })) {
    return 'expected a client awaiting its post-push report to never read as stale';
  }
});

check('isStale returns false for a recent collectedAt and true for one older than 48 hours', () => {
  const oneHourAgo = new Date(Date.now() - 1000 * 60 * 60).toISOString();
  const fiftyHoursAgo = new Date(Date.now() - 1000 * 60 * 60 * 50).toISOString();
  if (dashboard.isStale({ collectedAt: oneHourAgo })) return 'expected a 1-hour-old report to not be stale (default staleHours is 48)';
  if (!dashboard.isStale({ collectedAt: fiftyHoursAgo })) return 'expected a 50-hour-old report to be stale (default staleHours is 48)';
});

check('isStale treats an unparseable collectedAt/sourceUpdatedAt as stale, falling back correctly between the two fields', () => {
  if (!dashboard.isStale({ collectedAt: 'not-a-real-date' })) return 'expected an unparseable collectedAt to read as stale';
  if (!dashboard.isStale({})) return 'expected a client with neither collectedAt nor sourceUpdatedAt to read as stale';
});

check('safeId is deterministic and gives different ids for different input', () => {
  const a1 = dashboard.safeId('PC-ONE');
  const a2 = dashboard.safeId('PC-ONE');
  const b = dashboard.safeId('PC-TWO');
  if (a1 !== a2) return 'expected the same input to always produce the same id';
  if (a1 === b) return 'expected different input to produce a different id';
  if (!/^id-\d+$/.test(a1)) return 'expected the "id-<digits>" shape, got: ' + a1;
});

check('versionSortKey pads numeric segments so numeric order matches string order', () => {
  const low = dashboard.versionSortKey('16.0.4266.1001');
  const high = dashboard.versionSortKey('16.0.14334.20570');
  if (!(low < high)) return 'expected the padded key for the lower version to sort before the higher one, got ' + JSON.stringify([low, high]);
});

check('formatFileSize renders sub-MB sizes in KB and larger sizes in MB', () => {
  if (dashboard.formatFileSize(null) !== '') return 'expected an empty string for a null size';
  if (dashboard.formatFileSize(2048) !== '2.0 KB') return 'expected "2.0 KB" for 2048 bytes, got: ' + dashboard.formatFileSize(2048);
  if (dashboard.formatFileSize(5 * 1024 * 1024) !== '5.0 MB') return 'expected "5.0 MB" for 5 MiB, got: ' + dashboard.formatFileSize(5 * 1024 * 1024);
});

check('formatInstallDate reformats an 8-digit YYYYMMDD registry value to dd.MM.yyyy', () => {
  if (dashboard.formatInstallDate('20240305') !== '05.03.2024') return 'expected "05.03.2024", got: ' + dashboard.formatInstallDate('20240305');
});

check('formatInstallDate passes through anything that is not exactly 8 digits, including an already-formatted date', () => {
  if (dashboard.formatInstallDate('05.03.2024') !== '05.03.2024') return 'expected an already-formatted date to pass through unchanged';
  if (dashboard.formatInstallDate('202435') !== '202435') return 'expected a too-short value to pass through unchanged';
});

check('formatInstallDate passes through 8 digits that are not a real calendar date (bad month/day)', () => {
  if (dashboard.formatInstallDate('20241305') !== '20241305') return 'expected month 13 to be rejected and passed through unchanged';
  if (dashboard.formatInstallDate('20240232') !== '20240232') return 'expected day 32 to be rejected and passed through unchanged';
});

check('formatDateTime renders a falsy value as "Unknown" and an unparseable one via text()', () => {
  if (dashboard.formatDateTime(null) !== 'Unknown') return 'expected "Unknown" for null';
  if (dashboard.formatDateTime('not-a-date') !== 'not-a-date') return 'expected an unparseable value to fall back to its own text';
});

check('applySort sorts numerically ascending/descending and places null/undefined values last regardless of direction', () => {
  const items = [{ v: 3 }, { v: null }, { v: 1 }, { v: 2 }];
  const asc = dashboard.applySort(items, x => x.v, 1).map(x => x.v);
  const desc = dashboard.applySort(items, x => x.v, -1).map(x => x.v);
  if (JSON.stringify(asc) !== JSON.stringify([1, 2, 3, null])) return 'expected ascending order with null last, got: ' + JSON.stringify(asc);
  if (JSON.stringify(desc) !== JSON.stringify([3, 2, 1, null])) return 'expected descending order with null still last, got: ' + JSON.stringify(desc);
});

check('applySort does not mutate the array it was given', () => {
  const original = [{ v: 3 }, { v: 1 }, { v: 2 }];
  const originalOrder = original.map(x => x.v).join(',');
  dashboard.applySort(original, x => x.v, 1);
  if (original.map(x => x.v).join(',') !== originalOrder) return 'expected the input array to be left in its original order';
});

check('paginate slices the right page and clamps an out-of-range page number into [1, totalPages]', () => {
  const items = [1, 2, 3, 4, 5, 6, 7];
  const page2 = dashboard.paginate(items, 2, 3);
  if (JSON.stringify(page2.items) !== JSON.stringify([4, 5, 6])) return 'expected page 2 of size 3 to be [4,5,6], got: ' + JSON.stringify(page2.items);
  if (page2.totalPages !== 3) return 'expected 3 total pages for 7 items at size 3, got: ' + page2.totalPages;

  const tooHigh = dashboard.paginate(items, 99, 3);
  if (tooHigh.page !== 3) return 'expected an out-of-range page to clamp to the last real page (3), got: ' + tooHigh.page;

  const tooLow = dashboard.paginate(items, 0, 3);
  if (tooLow.page !== 1) return 'expected page 0 to clamp to page 1, got: ' + tooLow.page;
});

check('paginate always reports at least 1 total page, even for an empty array', () => {
  const empty = dashboard.paginate([], 1, 10);
  if (empty.totalPages !== 1) return 'expected totalPages 1 for an empty array, got: ' + empty.totalPages;
  if (empty.items.length !== 0) return 'expected no items for an empty array';
});

console.log('');
console.log(passed + ' passed, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);

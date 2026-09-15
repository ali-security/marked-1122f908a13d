const fs = require('fs');
const path = require('path');

const srcMarked = require('../../src/marked.js');
const libMarked = require('../../lib/marked.js');
const minMarked = require('../../marked.min.js');

const rootDir = path.resolve(__dirname, '../..');
const redosDir = path.resolve(__dirname, '../specs/redos');

// The exploits published with CVE-2022-21680 (block.def) and CVE-2022-21681
// (inline.reflink / inline.nolink, via inline.reflinkSearch). Each one drives
// the unpatched grammar into polynomial/exponential backtracking, so an
// unpatched build never finishes.
const attacks = [
  {
    name: 'cubic block.def backtracking (CVE-2022-21680)',
    markdown: require(path.join(redosDir, 'cubic_def.js')).markdown
  },
  {
    name: 'inline.reflinkSearch backtracking (CVE-2022-21681)',
    markdown: fs.readFileSync(path.join(redosDir, 'reflink_redos.md'), 'utf8')
  },
  {
    name: 'inline.nolink backtracking (CVE-2022-21681)',
    markdown: fs.readFileSync(path.join(redosDir, 'redos_nolink.md'), 'utf8')
  }
];

// src/ is the published `main`, lib/marked.js the published `browser` entry and
// marked.min.js the published standalone bundle - all of them ship in the
// tarball, so all of them must carry the fix.
const builds = [
  { name: 'src/marked.js', marked: srcMarked },
  { name: 'lib/marked.js', marked: libMarked },
  { name: 'marked.min.js', marked: minMarked }
];

// Files shipped in the tarball that embed a copy of the grammar.
const bundles = ['lib/marked.js', 'lib/marked.esm.js', 'marked.min.js'];

const vulnerable = {
  'block.def': ']: *\\n? *<?(',
  'block._label': '(?!\\s*\\])(?:\\\\[\\[\\]]|[^\\[\\]])+',
  'inline.reflink': '\\[(?!\\s*\\])((?:\\\\[\\[\\]]?|[^\\[\\]\\\\])+)\\]',
  'inline.nolink': '(?:\\[[^\\[\\]]*\\]|\\\\[\\[\\]]|[^\\[\\]])*'
};

const patched = {
  'block.def': ']: *(?:\\n *)?<?(',
  'block._label': '(?!\\s*\\])(?:\\\\.|[^\\[\\]\\\\])+',
  'inline.reflink': '\\[(label)\\]\\[(ref)\\]',
  'inline.nolink': '^!?\\[(ref)\\](?:\\[\\])?'
};

describe('ReDoS regressions (CVE-2022-21680, CVE-2022-21681)', () => {
  describe('grammar rules', () => {
    const expected = srcMarked.Lexer.rules;

    builds.forEach(build => {
      it(`${build.name} should compile the same rules as the patched source`, () => {
        const actual = build.marked.Lexer.rules;
        expect(actual.block.def.source).toBe(expected.block.def.source);
        expect(actual.block._label.source).toBe(expected.block._label.source);
        expect(actual.inline.reflink.source).toBe(expected.inline.reflink.source);
        expect(actual.inline.nolink.source).toBe(expected.inline.nolink.source);
        expect(actual.inline.reflinkSearch.source).toBe(expected.inline.reflinkSearch.source);
      });
    });
  });

  describe('shipped bundles', () => {
    bundles.forEach(bundle => {
      describe(bundle, () => {
        const source = fs.readFileSync(path.join(rootDir, bundle), 'utf8');

        Object.keys(vulnerable).forEach(rule => {
          it(`should not embed the vulnerable ${rule} pattern`, () => {
            expect(source).not.toContain(vulnerable[rule]);
            expect(source).toContain(patched[rule]);
          });
        });
      });
    });
  });

  builds.forEach(build => {
    describe(build.name, () => {
      attacks.forEach(attack => {
        it(`should not backtrack on ${attack.name}`, () => {
          const before = process.hrtime();
          const actual = build.marked(attack.markdown);
          const elapsed = process.hrtime(before);
          const seconds = elapsed[0] + elapsed[1] * 1e-9;

          expect(seconds).toBeLessThan(2);
          expect(actual).toBe(srcMarked(attack.markdown));
        });
      });
    });
  });
});

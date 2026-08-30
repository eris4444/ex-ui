// oxfmt ignores src/generated (.oxfmtrc.json), so handing it a staged set made
// up only of regenerated files leaves it with nothing to format and it exits 1
// with "Expected at least one target file". That is exactly what committing the
// output of `make gen` looks like, so the pre-commit hook rejected a routine
// commit. Filtering the generated tree out here keeps both tools off files they
// were never meant to touch.
const quote = (file) => JSON.stringify(file);

const isGenerated = (file) => file.replaceAll('\\', '/').includes('/src/generated/');

export default {
  'src/**/*.{ts,tsx}': (files) => {
    const targets = files.filter((file) => !isGenerated(file));
    if (targets.length === 0) return [];
    const args = targets.map(quote).join(' ');
    return [`oxfmt ${args}`, `oxlint --fix ${args}`];
  },
};

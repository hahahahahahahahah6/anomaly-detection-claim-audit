"""Offline documentation and Python AST audit."""
import argparse
import ast
import json
import os
from pathlib import Path
import re
import sys

from . import __version__
from .phrases import ANOMALY, NOANOMALY


def normalize(text):
    return ' '.join(text.lower().replace("n't", ' not').replace('-', ' ').split())


def prose(text):
    lines = []
    fence = None
    for line in text.splitlines():
        match = re.match(r'^ {0,3}(`{3,}|~{3,})(.*)$', line)
        if fence:
            if match and match[1][0] == fence[0] and len(match[1]) >= len(fence) and not match[2].strip():
                fence = None
        elif match:
            fence = match[1]
        else:
            lines.append(line)
    return '\n'.join(lines)


def _matches(text, phrases):
    pattern = r'\b(?:' + '|'.join(re.escape(p) for p in sorted(phrases, key=lambda p: (-len(p), p))) + r')\b'
    return list(re.finditer(pattern, text))


def claims(text):
    result = {'ANOMALY': [], 'NOANOMALY': []}
    for paragraph in re.split(r'\n\s*\n', prose(text)):
        value = normalize(paragraph)
        negative = _matches(value, NOANOMALY)
        result['NOANOMALY'].extend(m.group() for m in negative)
        chars = list(value)
        for match in negative:
            chars[match.start():match.end()] = ' ' * (match.end() - match.start())
        result['ANOMALY'].extend(m.group() for m in _matches(''.join(chars), ANOMALY))
    return result


SKLEARN = {
    'sklearn.ensemble.IsolationForest', 'sklearn.svm.OneClassSVM',
    'sklearn.neighbors.LocalOutlierFactor', 'sklearn.covariance.EllipticEnvelope',
    'sklearn.covariance.MinCovDet',
}
PYOD = {'IForest', 'LOF', 'OCSVM', 'COPOD', 'ECOD', 'HBOS', 'ABOD', 'KNN'}


def evidence(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    aliases = {}
    shadows = set()
    # Imports and definitions share one static module namespace. Nested imports
    # cannot establish module evidence; local definitions conservatively shadow.
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                aliases[alias.asname or alias.name] = node.module + '.' + alias.name
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            shadows.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            shadows.add(node.id)
        elif isinstance(node, ast.arg):
            shadows.add(node.arg)
    def resolve(node):
        if isinstance(node, ast.Name):
            return None if node.id in shadows else aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            base = resolve(node.value)
            return base + '.' + node.attr if base else None
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = resolve(node.func)
            if name in SKLEARN:
                return True
            if name:
                parts = name.split('.')
                if len(parts) >= 4 and parts[:2] == ['pyod', 'models'] and parts[-1] in PYOD:
                    return True
    return False


def audit(root, ignore=()):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise OSError('root must be an existing non-symlink directory')
    if not root.stat().st_mode & 0o444 or not root.stat().st_mode & 0o111:
        raise OSError('root is unreadable')
    prefixes = [Path(p).as_posix().strip('/') for p in ignore]
    def ignored(rel):
        name = rel.as_posix()
        return any(name == p or name.startswith(p + '/') for p in prefixes)
    found = {'ANOMALY': [], 'NOANOMALY': []}
    production = []
    tests = []
    def walk_error(error):
        raise error
    for base, dirs, files in os.walk(root, onerror=walk_error, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(base)/d).is_symlink() and not ignored((Path(base)/d).relative_to(root)))
        for filename in sorted(files):
            path = Path(base)/filename
            rel = path.relative_to(root)
            if path.is_symlink() or ignored(rel):
                continue
            if rel.as_posix() == 'README.md' or (path.suffix == '.md' and 'docs' in rel.parts[:-1]):
                for family, matches in claims(path.read_text(encoding='utf-8')).items():
                    if matches:
                        found[family].append(rel.as_posix())
            if path.suffix != '.py' or any(p in rel.parts[:-1] for p in ('fixtures', 'docs', 'examples')):
                continue
            if evidence(path.read_text(encoding='utf-8')):
                target = tests if 'tests' in rel.parts[:-1] or filename.startswith('test_') or filename.endswith('_test.py') else production
                target.append(rel.as_posix())
    findings = []
    if found['ANOMALY'] and not production:
        findings.append({'rule': 'documented-anomaly-claim-false', 'severity': 'MEDIUM' if tests else 'HIGH', 'documents': sorted(found['ANOMALY']), 'message': 'Evidence exists only in tests.' if tests else 'No production evidence found.'})
    if found['NOANOMALY'] and production:
        findings.append({'rule': 'documented-no-anomaly-claim-false', 'severity': 'HIGH', 'documents': sorted(found['NOANOMALY']), 'message': 'Production evidence contradicts the documented claim.'})
    return {'status': 'FAIL' if findings else 'PASS', 'findings': findings, 'production_evidence': sorted(production), 'test_evidence': sorted(tests)}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, self.prog + ': error: ' + message + '\n')


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument('root')
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--ignore', action='append', default=[])
    parser.add_argument('--fail-on', choices=('HIGH', 'MEDIUM', 'LOW'), default='HIGH')
    args = parser.parse_args(argv)
    try:
        result = audit(args.root, args.ignore)
    except (OSError, UnicodeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(result['status'])
        for finding in result['findings']:
            print('{severity} {rule}: {message}'.format(**finding))
        if args.verbose:
            print('Production evidence: ' + ', '.join(result['production_evidence']))
            print('Test evidence: ' + ', '.join(result['test_evidence']))
    ranks = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2}
    return 2 if any(ranks[f['severity']] >= ranks[args.fail_on] for f in result['findings']) else 0

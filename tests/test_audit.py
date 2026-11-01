import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from anomaly_detection_claim_audit.audit import audit, claims, evidence, main, normalize
from anomaly_detection_claim_audit.phrases import ANOMALY, NOANOMALY


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def put(self, name, text):
        path = self.root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def cli(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                code = main([str(self.root), *args])
            except SystemExit as error:
                code = error.code
        return code, output.getvalue()

    def test_phrase_counts_and_normalization(self):
        self.assertEqual(len(ANOMALY), 59)
        self.assertEqual(len(NOANOMALY), 30)
        self.assertEqual(len(set(ANOMALY)), 59)
        self.assertEqual(len(set(NOANOMALY)), 30)
        for phrase in ANOMALY:
            with self.subTest(phrase=phrase):
                self.assertEqual(normalize(phrase), phrase)
                self.assertEqual(claims(phrase), {'ANOMALY': [phrase], 'NOANOMALY': []})
        for phrase in NOANOMALY:
            with self.subTest(phrase=phrase):
                self.assertEqual(normalize(phrase), phrase)
                self.assertEqual(claims(phrase), {'ANOMALY': [], 'NOANOMALY': [phrase]})

    def test_text_rules(self):
        self.assertEqual(claims("Doesn't detect anomalies")['NOANOMALY'], ['does not detect anomalies'])
        self.assertEqual(claims('REAL-TIME anomaly detection')['ANOMALY'], ['real time anomaly detection'])
        self.assertFalse(claims('predetect anomaliesx')['ANOMALY'])
        self.assertFalse(claims('detect\n\nanomalies')['ANOMALY'])
        for fence in ('```', '~~~', '   ````'):
            self.assertFalse(claims(fence+'\ndetect anomalies\n'+fence)['ANOMALY'])
        self.assertEqual(claims('`detect anomalies`')['ANOMALY'], ['detect anomalies'])
        self.assertFalse(claims('anomaly anomalies outlier outliers fraud detection intrusion detection')['ANOMALY'])

    def test_sklearn_routes(self):
        for module, name in [('ensemble', 'IsolationForest'), ('svm', 'OneClassSVM'), ('neighbors', 'LocalOutlierFactor'), ('covariance', 'EllipticEnvelope'), ('covariance', 'MinCovDet')]:
            for source in [f'from sklearn.{module} import {name}\n{name}()', f'from sklearn.{module} import {name} as Detector\nDetector()', f'import sklearn.{module}\nsklearn.{module}.{name}()', f'from sklearn import {module}\n{module}.{name}()', f'import sklearn.{module} as lib\nlib.{name}()', f'from sklearn.{module} import {name}\nobj = {name}()\nobj.fit_predict(X)\nobj.predict(X)', f'from sklearn.{module} import {name}\n{name}().fit_predict(X)']:
                with self.subTest(source=source):
                    self.assertTrue(evidence(source))

    def test_pyod_routes(self):
        for name in ('IForest', 'LOF', 'OCSVM', 'COPOD', 'ECOD', 'HBOS', 'ABOD', 'KNN'):
            module = name.lower()
            for source in [f'from pyod.models.{module} import {name}\n{name}()', f'from pyod.models.{module} import {name} as D\nD()', f'import pyod.models.{module}\npyod.models.{module}.{name}()', f'from pyod.models import {module}\n{module}.{name}()', f'import pyod.models.{module} as m\nm.{name}()']:
                with self.subTest(source=source):
                    self.assertTrue(evidence(source))

    def test_non_evidence(self):
        cases = ['from sklearn.svm import SVC\nSVC()', 'from sklearn.ensemble import RandomForestClassifier\nRandomForestClassifier()', 'from sklearn.linear_model import LogisticRegression\nLogisticRegression()', 'from sklearn.linear_model import LinearRegression\nLinearRegression()', 'from sklearn.cluster import KMeans, DBSCAN, HDBSCAN\nKMeans()\nDBSCAN()\nHDBSCAN()', 'from sklearn.neighbors import NearestNeighbors, KNN\nNearestNeighbors().kneighbors(X)\nKNN()', 'from other import KNN\nKNN()', 'sorted(X)\nX.sort()', 'df.groupby("key")', 'from itertools import groupby\ngroupby(X)', 'groups = {}\ngroups[key] = value', 'query = "SELECT key FROM data GROUP BY key"', 'from sklearn.feature_extraction.text import TfidfVectorizer\nTfidfVectorizer()', 'from sklearn.decomposition import PCA, TruncatedSVD\nPCA()\nTruncatedSVD()', 'from sklearn.metrics import silhouette_score\nsilhouette_score(X, y)', 'from scipy.stats import zscore\nzscore(X) > 3', 'df.rolling(10).mean() + df.rolling(10).std() > 3', 'from sklearn.datasets import make_blobs, make_circles, load_iris\nmake_blobs()\nmake_circles()\nload_iris()', 'from sklearn.ensemble import IsolationForest', 'from sklearn.ensemble import IsolationForest\nIsolationForest', 'text = "IsolationForest()"', 'import subprocess\nsubprocess.run(["IsolationForest"])', 'obj.fit(X)\nobj.predict(X)', 'invalid syntax !']
        for source in cases:
            with self.subTest(source=source):
                self.assertFalse(evidence(source))

    def test_shadowing(self):
        for definition in ('class IsolationForest: pass', 'def IsolationForest(): pass', 'IsolationForest = other'):
            self.assertFalse(evidence('from sklearn.ensemble import IsolationForest\n'+definition+'\nIsolationForest()'))
        self.assertFalse(evidence('import sklearn as s\ns = other\ns.ensemble.IsolationForest()'))

    def test_scope_and_symlinks(self):
        self.put('other.md', 'detect anomalies')
        self.assertEqual(audit(self.root)['status'], 'PASS')
        self.put('nested/docs/page.md', 'detect anomalies')
        source = 'from sklearn.ensemble import IsolationForest\nIsolationForest()'
        for name in ('fixtures/a.py', 'docs/a.py', 'examples/a.py'):
            self.put(name, source)
        self.assertEqual(audit(self.root)['findings'][0]['severity'], 'HIGH')
        self.put('real.py', source)
        (self.root/'link.py').symlink_to(self.root/'real.py')
        (self.root/'linked').symlink_to(self.root/'fixtures', target_is_directory=True)
        result = audit(self.root)
        self.assertEqual(result['production_evidence'], ['real.py'])
        self.assertEqual(audit(self.root, ['real.py'])['findings'][0]['severity'], 'HIGH')
        self.assertEqual(audit(self.root, ['nested'])['status'], 'PASS')

    def test_findings_and_cli(self):
        self.put('README.md', 'detect anomalies')
        code, output = self.cli('--json')
        self.assertEqual(code, 2)
        finding = json.loads(output)['findings'][0]
        self.assertEqual(finding['rule'], 'documented-anomaly-claim-false')
        self.assertEqual(finding['severity'], 'HIGH')
        for filename in ('tests/model.py', 'test_model.py', 'model_test.py'):
            self.put(filename, 'from pyod.models.lof import LOF\nLOF()')
        self.assertEqual(self.cli()[0], 0)
        self.assertIn('MEDIUM', self.cli()[1])
        self.assertEqual(self.cli('--fail-on', 'MEDIUM')[0], 2)
        self.assertIn('Test evidence:', self.cli('--verbose')[1])
        self.assertEqual(self.cli('--ignore', 'README.md')[0], 0)
        self.put('README.md', 'no anomaly detection')
        self.assertEqual(self.cli()[0], 0)
        self.put('app.py', 'from sklearn.svm import OneClassSVM\nOneClassSVM()')
        code, output = self.cli('--json')
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output)['findings'][0]['rule'], 'documented-no-anomaly-claim-false')
        self.assertEqual(json.loads(output)['findings'][0]['severity'], 'HIGH')

    def test_errors_version_and_empty(self):
        self.assertEqual(self.cli()[0], 0)
        self.assertEqual(self.cli('--version'), (0, '0.1.0\n'))
        self.assertEqual(self.cli('--unknown')[0], 1)
        self.assertEqual(self.cli('--fail-on', 'INVALID')[0], 1)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.root/'absent')]), 1)
            with self.assertRaises(SystemExit) as error:
                main([])
            self.assertEqual(error.exception.code, 1)
        self.root.chmod(0)
        try:
            self.assertEqual(self.cli()[0], 1)
        finally:
            self.root.chmod(0o700)

    def test_project_self_audit(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(audit(root)['status'], 'PASS')
        self.assertEqual(claims((root/'README.md').read_text()), {'ANOMALY': [], 'NOANOMALY': []})


if __name__ == '__main__':
    unittest.main()

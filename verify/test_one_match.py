#!/usr/bin/env python3
"""Offline test: one match, one record. A second winlew.game.result record committing to the same
sessionCommitment is found as a duplicate; a record for another match, or the record itself, is not.
Standard library only; works on a temporary copy of this repository's records and archive.

    python -I verify/test_one_match.py
"""
import copy
import importlib.util
import json
import os
import shutil
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location('verify_evidence', os.path.join(HERE, 'verify_evidence.py'))
ve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ve)

PILOT = 'records/sequence/2026/10/18/20-20cd1369a0ea079400bbf1cd245dc5ef50496b3bf0f2f3fbad4288c8cb3d7ae7.json'


class OneMatchOneRecord(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        shutil.copytree(os.path.join(ROOT, 'records'), os.path.join(self.root, 'records'))
        shutil.copytree(os.path.join(ROOT, 'blobs'), os.path.join(self.root, 'blobs'))
        self.bundle = json.load(open(os.path.join(ROOT, PILOT), encoding='utf-8'))
        self.record = self.bundle['record']
        sha = self.record['content']['sha256']
        self.content = json.load(open(os.path.join(ROOT, 'blobs', 'sha256', sha[:2], sha + '.json'), encoding='utf-8'))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write_record(self, name, record, content=None):
        if content is not None:
            raw = json.dumps(content).encode('utf-8')
            import hashlib
            sha = hashlib.sha256(raw).hexdigest()
            d = os.path.join(self.root, 'blobs', 'sha256', sha[:2])
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, sha + '.json'), 'wb').write(raw)
            record = {**record, 'content': {**record['content'], 'sha256': sha, 'bytes': len(raw)}}
        d = os.path.join(self.root, 'records', 'sequence', '2026', '11', '01')
        os.makedirs(d, exist_ok=True)
        json.dump({**self.bundle, 'record': record}, open(os.path.join(d, name), 'w', encoding='utf-8'))
        return ve.xyo_hash(record)

    def test_the_published_pilot_has_no_duplicate(self):
        self.assertEqual(ve.same_match_records(ROOT, ve.xyo_hash(self.record), self.content['sessionCommitment']), [])

    def test_a_second_record_for_the_same_match_is_a_duplicate(self):
        again = copy.deepcopy(self.record)
        again['issuedAt'] = self.record['issuedAt'] + 60_000           # a different record, the same match
        dup = self.write_record('00-duplicate.json', again)
        found = ve.same_match_records(self.root, ve.xyo_hash(self.record), self.content['sessionCommitment'])
        self.assertEqual(found, [dup])
        # And from the duplicate's side, the original is the other record.
        self.assertEqual(ve.same_match_records(self.root, dup, self.content['sessionCommitment']), [ve.xyo_hash(self.record)])

    def test_a_different_match_is_not_a_duplicate(self):
        other = copy.deepcopy(self.record)
        other['issuedAt'] = self.record['issuedAt'] + 120_000
        self.write_record('01-other-match.json', other, {**self.content, 'sessionCommitment': 'ab' * 32})
        self.assertEqual(ve.same_match_records(self.root, ve.xyo_hash(self.record), self.content['sessionCommitment']), [])

    def test_other_claim_types_are_ignored(self):
        reward = copy.deepcopy(self.record)
        reward['claim'] = {**reward['claim'], 'type': 'winlew.reward.trail'}
        self.write_record('02-reward.json', reward)
        self.assertEqual(ve.same_match_records(self.root, ve.xyo_hash(self.record), self.content['sessionCommitment']), [])

    def test_unreadable_files_are_skipped_not_fatal(self):
        d = os.path.join(self.root, 'records', 'sequence', '2026', '11', '01')
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, '03-broken.json'), 'w').write('{not json')
        self.assertEqual(ve.same_match_records(self.root, ve.xyo_hash(self.record), self.content['sessionCommitment']), [])


if __name__ == '__main__':
    unittest.main(verbosity=1)

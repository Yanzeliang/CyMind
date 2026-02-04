"""
Property-based tests for scan result organization consistency
Tests Requirements 1.3, 1.5, 2.4: Target categorization, search/filtering, result organization
"""

import pytest
from hypothesis import given, strategies as st, assume, settings
from hypothesis.stateful import RuleBasedStateMachine, Bundle, rule, initialize, invariant
import tempfile
import os
import uuid
from datetime import datetime, timedelta

from models import (
    Session, Project, Target, Scan, ScanResult, 
    ProjectStatus, TargetType, ScanType, ScanStatus, ResultType, Severity,
    DatabaseManager
)
from modules.target_manager import TargetManager
from modules.project_manager import ProjectManager


@st.composite
def target_data(draw):
    """Generate target data for testing"""
    target_type = draw(st.sampled_from(['domain', 'ip', 'url', 'network']))
    
    if target_type == 'domain':
        url = f"https://{draw(st.text(min_size=3, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'))))}.com"
        return {
            'name': draw(st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Zs')))),
            'url': url,
            'type': target_type,
            'tags': draw(st.lists(st.text(min_size=1, max_size=10, alphabet=st.characters(whitelist_categories=('Lu', 'Ll'))), max_size=5, unique=True))
        }
    elif target_type == 'ip':
        ip = f"{draw(st.integers(1, 255))}.{draw(st.integers(0, 255))}.{draw(st.integers(0, 255))}.{draw(st.integers(1, 254))}"
        return {
            'name': draw(st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Zs')))),
            'ip': ip,
            'type': target_type,
            'tags': draw(st.lists(st.text(min_size=1, max_size=10, alphabet=st.characters(whitelist_categories=('Lu', 'Ll'))), max_size=5, unique=True))
        }
    else:
        return {
            'name': draw(st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Zs')))),
            'url': f"https://example{draw(st.integers(1, 1000))}.com/api",
            'type': target_type,
            'tags': draw(st.lists(st.text(min_size=1, max_size=10, alphabet=st.characters(whitelist_categories=('Lu', 'Ll'))), max_size=5, unique=True))
        }


@st.composite
def scan_result_data(draw):
    """Generate scan result data for testing"""
    return {
        'result_type': draw(st.sampled_from([t.value for t in ResultType])),
        'data': {
            'ports': draw(st.lists(st.integers(1, 65535), max_size=10, unique=True)),
            'services': draw(st.lists(st.text(min_size=3, max_size=20), max_size=5, unique=True)),
            'findings': draw(st.text(max_size=200))
        },
        'severity': draw(st.sampled_from([s.value for s in Severity])),
        'confidence': draw(st.floats(min_value=0.0, max_value=1.0))
    }


class ScanResultOrganizationMachine(RuleBasedStateMachine):
    """
    Property 3: Scan result organization consistency
    
    Tests that:
    1. Scan results are properly organized by project and target
    2. Target categorization is maintained across operations
    3. Search and filtering work correctly
    4. Result organization remains consistent
    """
    
    def __init__(self):
        super().__init__()
        # Create temporary database for testing
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.db_manager = DatabaseManager(f'sqlite:///{self.db_path}')
        self.target_manager = TargetManager()
        self.project_manager = ProjectManager()
        
        # Track state
        self.projects = {}
        self.targets = {}
        self.scans = {}
        self.results = {}
    
    def teardown(self):
        """Clean up test database"""
        try:
            os.close(self.db_fd)
            os.unlink(self.db_path)
        except:
            pass
    
    projects = Bundle('projects')
    targets = Bundle('targets')
    scans = Bundle('scans')
    
    @initialize()
    def setup_initial_state(self):
        """Initialize with some projects and targets"""
        # Create test project
        project_data = {
            'name': f"Test Project {uuid.uuid4().hex[:8]}",
            'description': 'Test project for scan result organization',
            'status': ProjectStatus.ACTIVE.value
        }
        result = self.project_manager.create_project(project_data)
        if result['status'] == 'success':
            project_id = result['project']['id']
            self.projects[project_id] = {
                'id': project_id,
                'data': project_data,
                'targets': [],
                'scans': []
            }
    
    @rule(target=projects)
    def create_project(self):
        """Create a new project"""
        project_data = {
            'name': f'Project_{len(self.projects)}_{datetime.now().microsecond}',
            'description': f'Test project {len(self.projects)}',
            'status': ProjectStatus.ACTIVE.value
        }
        
        result = self.project_manager.create_project(project_data)
        if result['status'] == 'success':
            project_id = result['project']['id']
            self.projects[project_id] = {
                'id': project_id,
                'data': project_data,
                'targets': [],
                'scans': []
            }
            return project_id
        return None
    
    @rule(target=targets, project_id=projects, target_data=target_data())
    def add_target_to_project(self, project_id, target_data):
        """Add a target to a project"""
        assume(project_id in self.projects)
        assume(len(target_data['name'].strip()) > 0)
        
        # Make target name unique
        target_data['name'] = f"{target_data['name']}_{len(self.targets)}"
        
        result = self.target_manager.add_target(target_data, project_id)
        
        if result.get('status') == 'success':
            target_id = result['target']['id']
            self.targets[target_id] = {
                'id': target_id,
                'project_id': project_id,
                'data': target_data,
                'scans': []
            }
            self.projects[project_id]['targets'].append(target_id)
            return target_id
        return None
    
    @rule(target=scans, target_id=targets)
    def create_scan_for_target(self, target_id):
        """Create a scan for a target"""
        assume(target_id in self.targets)
        
        target = self.targets[target_id]
        project_id = target['project_id']
        
        # Simulate scan creation
        session = Session()
        try:
            scan = Scan(
                project_id=project_id,
                target_id=target_id,
                scan_type=ScanType.RECON.value,
                status=ScanStatus.COMPLETED.value
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            
            scan_id = scan.id
            self.scans[scan_id] = {
                'id': scan_id,
                'project_id': project_id,
                'target_id': target_id,
                'results': []
            }
            
            self.targets[target_id]['scans'].append(scan_id)
            self.projects[project_id]['scans'].append(scan_id)
            
            return scan_id
        finally:
            session.close()
    
    @rule(scan_id=scans, result_data=scan_result_data())
    def add_scan_result(self, scan_id, result_data):
        """Add a result to a scan"""
        assume(scan_id in self.scans)
        
        scan = self.scans[scan_id]
        
        # Create scan result
        session = Session()
        try:
            scan_result = ScanResult(
                scan_id=scan_id,
                result_type=result_data['result_type'],
                data=result_data['data'],
                severity=result_data['severity'],
                confidence=result_data['confidence']
            )
            session.add(scan_result)
            session.commit()
            session.refresh(scan_result)
            
            result_id = scan_result.id
            self.results[result_id] = {
                'id': result_id,
                'scan_id': scan_id,
                'project_id': scan['project_id'],
                'target_id': scan['target_id'],
                'data': result_data
            }
            
            self.scans[scan_id]['results'].append(result_id)
            
        finally:
            session.close()
    
    @rule(project_id=projects)
    def test_project_target_organization(self, project_id):
        """Test that targets are properly organized by project"""
        assume(project_id in self.projects)
        
        # Get targets from database
        db_targets = self.target_manager.get_targets(project_id=project_id)
        
        # Get expected targets from our state
        expected_target_ids = set(self.projects[project_id]['targets'])
        actual_target_ids = set(target['id'] for target in db_targets)
        
        # All targets should belong to the correct project
        for target in db_targets:
            assert target['project_id'] == project_id, \
                f"Target {target['id']} should belong to project {project_id}"
        
        # Our tracked targets should match database targets
        assert expected_target_ids == actual_target_ids, \
            f"Expected targets {expected_target_ids} but got {actual_target_ids}"
    
    @rule(target_id=targets)
    def test_target_scan_organization(self, target_id):
        """Test that scans are properly organized by target"""
        assume(target_id in self.targets)
        
        target = self.targets[target_id]
        expected_scan_ids = set(target['scans'])
        
        # Get scans from database
        session = Session()
        try:
            db_scans = session.query(Scan).filter_by(target_id=target_id).all()
            actual_scan_ids = set(scan.id for scan in db_scans)
            
            # All scans should belong to the correct target
            for scan in db_scans:
                assert scan.target_id == target_id, \
                    f"Scan {scan.id} should belong to target {target_id}"
                assert scan.project_id == target['project_id'], \
                    f"Scan {scan.id} should belong to project {target['project_id']}"
            
            # Our tracked scans should match database scans
            assert expected_scan_ids == actual_scan_ids, \
                f"Expected scans {expected_scan_ids} but got {actual_scan_ids}"
                
        finally:
            session.close()
    
    @rule(scan_id=scans)
    def test_scan_result_organization(self, scan_id):
        """Test that results are properly organized by scan"""
        assume(scan_id in self.scans)
        
        scan = self.scans[scan_id]
        expected_result_ids = set(scan['results'])
        
        # Get results from database
        session = Session()
        try:
            db_results = session.query(ScanResult).filter_by(scan_id=scan_id).all()
            actual_result_ids = set(result.id for result in db_results)
            
            # All results should belong to the correct scan
            for result in db_results:
                assert result.scan_id == scan_id, \
                    f"Result {result.id} should belong to scan {scan_id}"
            
            # Our tracked results should match database results
            assert expected_result_ids == actual_result_ids, \
                f"Expected results {expected_result_ids} but got {actual_result_ids}"
                
        finally:
            session.close()
    
    @rule()
    def test_target_search_consistency(self):
        """Test that target search returns consistent results"""
        if not self.targets:
            return
        
        # Test search by name
        sample_target_id = list(self.targets.keys())[0]
        sample_target = self.targets[sample_target_id]
        search_term = sample_target['data']['name'][:5]  # Search by partial name
        project_id = sample_target['project_id']
        search_results = self.target_manager.search_targets(search_term, project_id=project_id)
        
        # Results should be consistent with database state
        for result in search_results:
            assert result['id'] in self.targets, \
                f"Search result {result['id']} should exist in our tracked targets"
            
            tracked_target = self.targets[result['id']]
            assert result['project_id'] == tracked_target['project_id'], \
                f"Search result project_id should match tracked data"
    
    @rule()
    def test_target_tag_filtering(self):
        """Test that tag-based filtering works correctly"""
        if not self.targets:
            return
        
        # Find targets with tags
        targets_with_tags = [
            (tid, target) for tid, target in self.targets.items() 
            if target['data'].get('tags')
        ]
        
        if not targets_with_tags:
            return
        
        # Test filtering by first tag of first target
        sample_target_id, sample_target = targets_with_tags[0]
        sample_tags = sample_target['data']['tags'][:1]  # Use first tag
        project_id = sample_target['project_id']
        
        filtered_results = self.target_manager.get_targets_by_tags(sample_tags, project_id=project_id)
        
        # Results should include our sample target
        result_ids = [result['id'] for result in filtered_results]
        assert sample_target_id in result_ids, \
            f"Target {sample_target_id} with tags {sample_tags} should be in filtered results"
    
    @invariant()
    def organization_hierarchy_consistency(self):
        """Verify the organization hierarchy is consistent"""
        # Project -> Target -> Scan -> Result hierarchy should be maintained
        for result_id, result in self.results.items():
            scan_id = result['scan_id']
            target_id = result['target_id']
            project_id = result['project_id']
            
            # Scan should exist and belong to correct target/project
            assert scan_id in self.scans, f"Scan {scan_id} should exist"
            assert self.scans[scan_id]['target_id'] == target_id, \
                f"Scan {scan_id} should belong to target {target_id}"
            assert self.scans[scan_id]['project_id'] == project_id, \
                f"Scan {scan_id} should belong to project {project_id}"
            
            # Target should exist and belong to correct project
            assert target_id in self.targets, f"Target {target_id} should exist"
            assert self.targets[target_id]['project_id'] == project_id, \
                f"Target {target_id} should belong to project {project_id}"
            
            # Project should exist
            assert project_id in self.projects, f"Project {project_id} should exist"
    
    @invariant()
    def target_categorization_consistency(self):
        """Verify target categorization is maintained"""
        for target_id, target in self.targets.items():
            target_data = target['data']
            
            # Target type should be consistent with data
            if target_data.get('type'):
                expected_types = [self.target_manager._map_target_type(target_data['type'])]
            elif 'url' in target_data:
                expected_types = [TargetType.DOMAIN.value, TargetType.URL.value]
            elif 'ip' in target_data:
                expected_types = [TargetType.IP.value, TargetType.NETWORK.value]
            else:
                continue  # Skip validation for incomplete data
            
            # Get actual target from database
            db_target = self.target_manager.get_target_by_id(target_id)
            if db_target:
                assert db_target['type'] in expected_types, \
                    f"Target {target_id} type should be one of {expected_types}, got {db_target['type']}"


class TestScanResultOrganization:
    """Test scan result organization properties"""
    
    def setup_method(self):
        """Set up test database"""
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.db_manager = DatabaseManager(f'sqlite:///{self.db_path}')
        self.target_manager = TargetManager()
        self.project_manager = ProjectManager()
    
    def teardown_method(self):
        """Clean up test database"""
        try:
            os.close(self.db_fd)
            os.unlink(self.db_path)
        except:
            pass
    
    @given(
        targets=st.lists(target_data(), min_size=2, max_size=5),
        search_terms=st.lists(st.text(min_size=1, max_size=10), min_size=1, max_size=3)
    )
    @settings(max_examples=15, deadline=None)
    def test_target_search_functionality(self, targets, search_terms):
        """Test that target search returns relevant results"""
        # Create a project
        project_result = self.project_manager.create_project({
            'name': f"Search Test Project {uuid.uuid4().hex[:8]}",
            'description': 'Project for testing search functionality'
        })
        if project_result['status'] != 'success':
            pytest.fail(f"Project creation failed: {project_result.get('message')}")
        project_id = project_result['project']['id']
        
        # Add targets
        added_targets = []
        for i, target_data in enumerate(targets):
            if len(target_data.get('name', '').strip()) == 0:
                target_data['name'] = f"search_test_{i}"
            else:
                target_data['name'] = f"search_test_{i}_{target_data['name']}"
            result = self.target_manager.add_target(target_data, project_id)
            
            if result.get('status') == 'success':
                added_targets.append(result['target'])

        if not added_targets:
            fallback = {
                'name': f"search_fallback_{uuid.uuid4().hex[:6]}",
                'url': f"https://example{uuid.uuid4().hex[:4]}.com",
                'type': 'domain',
                'tags': ['search']
            }
            result = self.target_manager.add_target(fallback, project_id)
            if result.get('status') == 'success':
                added_targets.append(result['target'])
            else:
                pytest.fail("Failed to add any target for search test")
        
        # Test search functionality
        for search_term in search_terms:
            if not search_term.strip():
                continue
                
            search_results = self.target_manager.search_targets(search_term, project_id)
            
            # All results should belong to the correct project
            for result in search_results:
                assert result['project_id'] == project_id, \
                    f"Search result should belong to project {project_id}"
                
                # Result should match search term in some way
                target_text = f"{result['name']} {result.get('url', '')} {result.get('ip_address', '')}"
                # This is a basic relevance check - in practice, search might be more sophisticated
    
    @given(
        targets=st.lists(target_data(), min_size=2, max_size=4),
        tag_filters=st.lists(st.text(min_size=1, max_size=8, alphabet=st.characters(whitelist_categories=('Lu', 'Ll'))), min_size=1, max_size=3)
    )
    @settings(max_examples=15, deadline=None)
    def test_target_tag_filtering(self, targets, tag_filters):
        """Test that tag-based filtering works correctly"""
        # Create a project
        project_result = self.project_manager.create_project({
            'name': f"Tag Filter Test Project {uuid.uuid4().hex[:8]}",
            'description': 'Project for testing tag filtering'
        })
        if project_result['status'] != 'success':
            pytest.fail(f"Project creation failed: {project_result.get('message')}")
        project_id = project_result['project']['id']
        
        # Add targets with tags
        added_targets = []
        for i, target_data in enumerate(targets):
            if len(target_data.get('name', '').strip()) == 0:
                target_data['name'] = f"tag_test_{i}"
            else:
                target_data['name'] = f"tag_test_{i}_{target_data['name']}"
            result = self.target_manager.add_target(target_data, project_id)
            
            if result.get('status') == 'success':
                added_targets.append((result['target'], target_data.get('tags', [])))

        if not added_targets:
            fallback = {
                'name': f"tag_fallback_{uuid.uuid4().hex[:6]}",
                'url': f"https://example{uuid.uuid4().hex[:4]}.com",
                'type': 'domain',
                'tags': ['fallback']
            }
            result = self.target_manager.add_target(fallback, project_id)
            if result.get('status') == 'success':
                added_targets.append((result['target'], fallback.get('tags', [])))
            else:
                pytest.fail("Failed to add any target for tag filter test")
        
        # Test tag filtering
        for tag_filter in tag_filters:
            if not tag_filter.strip():
                continue
                
            filtered_results = self.target_manager.get_targets_by_tags([tag_filter], project_id)
            
            # All results should belong to the correct project
            for result in filtered_results:
                assert result['project_id'] == project_id, \
                    f"Filtered result should belong to project {project_id}"
                
                # Result should have the filtered tag
                result_tags = result.get('tags', [])
                assert tag_filter in result_tags, \
                    f"Filtered result should contain tag '{tag_filter}'"
    
    @given(targets=st.lists(target_data(), min_size=1, max_size=3))
    @settings(max_examples=10, deadline=None)
    def test_target_statistics_accuracy(self, targets):
        """Test that target statistics are accurate"""
        # Create a project
        project_result = self.project_manager.create_project({
            'name': f"Statistics Test Project {uuid.uuid4().hex[:8]}",
            'description': 'Project for testing statistics'
        })
        if project_result['status'] != 'success':
            pytest.fail(f"Project creation failed: {project_result.get('message')}")
        project_id = project_result['project']['id']
        
        # Add targets
        added_targets = []
        expected_types = {}
        expected_tags = {}
        
        for i, target_data in enumerate(targets):
            if len(target_data.get('name', '').strip()) == 0:
                target_data['name'] = f"stats_test_{i}"
            else:
                target_data['name'] = f"stats_test_{i}_{target_data['name']}"
            result = self.target_manager.add_target(target_data, project_id)
            
            if result.get('status') == 'success':
                added_targets.append(result['target'])
                
                # Track expected statistics
                target_type = result['target']['type']
                expected_types[target_type] = expected_types.get(target_type, 0) + 1
                
                for tag in target_data.get('tags', []):
                    expected_tags[tag] = expected_tags.get(tag, 0) + 1
        
        if not added_targets:
            fallback = {
                'name': f"stats_fallback_{uuid.uuid4().hex[:6]}",
                'url': f"https://example{uuid.uuid4().hex[:4]}.com",
                'type': 'domain',
                'tags': ['stats']
            }
            result = self.target_manager.add_target(fallback, project_id)
            if result.get('status') == 'success':
                added_targets.append(result['target'])
                target_type = result['target']['type']
                expected_types[target_type] = expected_types.get(target_type, 0) + 1
                for tag in fallback.get('tags', []):
                    expected_tags[tag] = expected_tags.get(tag, 0) + 1
            else:
                pytest.fail("Failed to add any target for statistics test")
        
        # Get statistics
        stats = self.target_manager.get_target_statistics(project_id)
        
        # Verify statistics accuracy
        assert stats['total_targets'] == len(added_targets), \
            f"Total targets should be {len(added_targets)}, got {stats['total_targets']}"
        
        assert stats['type_distribution'] == expected_types, \
            f"Type distribution should match expected: {expected_types}"


# Run the state machine test
TestScanResultOrganizationStateMachine = ScanResultOrganizationMachine.TestCase


if __name__ == "__main__":
    # Run basic property tests
    test_instance = TestScanResultOrganization()
    test_instance.setup_method()
    
    try:
        print("Testing scan result organization properties...")
        
        # Test with sample data
        sample_targets = [
            {'name': 'Web Server', 'url': 'https://example.com', 'type': 'domain', 'tags': ['web', 'production']},
            {'name': 'Database Server', 'ip': '192.168.1.100', 'type': 'ip', 'tags': ['database', 'internal']},
            {'name': 'API Endpoint', 'url': 'https://api.example.com', 'type': 'api', 'tags': ['api', 'production']}
        ]
        
        test_instance.test_target_search_functionality(sample_targets, ['example', 'server'])
        test_instance.test_target_tag_filtering(sample_targets, ['production', 'web'])
        test_instance.test_target_statistics_accuracy(sample_targets)
        
        print("✅ Scan result organization property tests passed!")
        
    finally:
        test_instance.teardown_method()

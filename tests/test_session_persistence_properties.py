"""
Property-based tests for session persistence consistency.

Feature: cymind-enhancement, Property 17: Session persistence consistency
For any project management operation, state should be maintained across 
sessions and properly restored.
"""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
import tempfile
import os

from models import Project, Target, Scan, ScanResult, ProjectStatus, TargetType, ScanType, ScanStatus, ResultType, Severity, DatabaseManager


class TestSessionPersistenceConsistency:
    """Test session persistence consistency properties"""
    
    def create_temp_db_path(self):
        """Create temporary database file path"""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        temp_file.close()
        return temp_file.name
    
    def create_db_manager(self, db_path):
        """Create database manager for given path"""
        return DatabaseManager(f'sqlite:///{db_path}')
    
    @given(
        project_data=st.fixed_dictionaries({
            'name': st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd'))),
            'description': st.text(max_size=500),
            'status': st.sampled_from([s.value for s in ProjectStatus])
        }),
        target_data=st.fixed_dictionaries({
            'name': st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd'))),
            'url': st.text(min_size=10, max_size=100).map(lambda x: f"https://{x}.example.com"),
            'target_type': st.sampled_from([t.value for t in TargetType]),
            'tags': st.lists(st.text(min_size=1, max_size=20), max_size=5)
        })
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_project_state_persistence_across_sessions(self, project_data, target_data):
        """
        Property 17: Session persistence consistency
        Validates: Requirements 5.2
        
        For any project created in one session, it should be fully recoverable 
        with all associated data in subsequent sessions.
        """
        temp_db_path = self.create_temp_db_path()
        
        try:
            # Session 1: Create project and target
            db_manager1 = self.create_db_manager(temp_db_path)
            session1 = db_manager1.get_session()
            
            original_project_id = None
            original_target_id = None
            
            try:
                # Create project
                project = Project(**project_data)
                session1.add(project)
                session1.commit()
                original_project_id = project.id
                
                # Create target
                target = Target(
                    project_id=project.id,
                    **target_data
                )
                session1.add(target)
                session1.commit()
                original_target_id = target.id
                
            finally:
                session1.close()
                db_manager1.close_session()
            
            # Session 2: Verify persistence
            db_manager2 = self.create_db_manager(temp_db_path)
            session2 = db_manager2.get_session()
            
            try:
                # Property: Project should exist and be recoverable
                recovered_project = session2.query(Project).filter_by(id=original_project_id).first()
                assert recovered_project is not None, "Project should persist across sessions"
                
                # Property: All project attributes should be preserved
                assert recovered_project.name == project_data['name'], "Project name should persist"
                assert recovered_project.description == project_data['description'], "Project description should persist"
                assert recovered_project.status == project_data['status'], "Project status should persist"
                
                # Property: Target should exist and be associated
                recovered_target = session2.query(Target).filter_by(id=original_target_id).first()
                assert recovered_target is not None, "Target should persist across sessions"
                assert recovered_target.project_id == original_project_id, "Target-project association should persist"
                
                # Property: All target attributes should be preserved
                assert recovered_target.name == target_data['name'], "Target name should persist"
                assert recovered_target.url == target_data['url'], "Target URL should persist"
                assert recovered_target.target_type == target_data['target_type'], "Target type should persist"
                assert recovered_target.tags == target_data['tags'], "Target tags should persist"
                
                # Property: Relationships should be intact
                assert len(recovered_project.targets) == 1, "Project should have one target"
                assert recovered_project.targets[0].id == original_target_id, "Project should reference correct target"
                
            finally:
                session2.close()
                db_manager2.close_session()
        
        finally:
            # Cleanup temp file
            if os.path.exists(temp_db_path):
                os.unlink(temp_db_path)
    
    @given(
        scan_operations=st.lists(
            st.fixed_dictionaries({
                'scan_type': st.sampled_from([s.value for s in ScanType]),
                'status': st.sampled_from([s.value for s in ScanStatus]),
                'configuration': st.dictionaries(
                    st.text(min_size=1, max_size=20), 
                    st.one_of(st.text(max_size=50), st.integers(), st.booleans()),
                    max_size=5
                )
            }),
            min_size=1, max_size=5
        )
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_scan_state_persistence_across_sessions(self, scan_operations):
        """
        Property 17: Session persistence consistency (scan operations)
        Validates: Requirements 5.2
        
        For any scan operations performed across multiple sessions, 
        the scan state and progress should be consistently maintained.
        """
        temp_db_path = self.create_temp_db_path()
        
        try:
            # Session 1: Setup project and target
            db_manager1 = self.create_db_manager(temp_db_path)
            session1 = db_manager1.get_session()
            
            project_id = None
            target_id = None
            
            try:
                project = Project(
                    name="persistence_test_project",
                    description="Test project for persistence",
                    status=ProjectStatus.ACTIVE.value
                )
                session1.add(project)
                session1.commit()
                project_id = project.id
                
                target = Target(
                    project_id=project.id,
                    name="test_target",
                    url="https://test.example.com",
                    target_type=TargetType.DOMAIN.value
                )
                session1.add(target)
                session1.commit()
                target_id = target.id
                
            finally:
                session1.close()
                db_manager1.close_session()
            
            # Session 2: Create scans
            db_manager2 = self.create_db_manager(temp_db_path)
            session2 = db_manager2.get_session()
            
            scan_ids = []
            
            try:
                for scan_op in scan_operations:
                    scan = Scan(
                        project_id=project_id,
                        target_id=target_id,
                        scan_type=scan_op['scan_type'],
                        status=scan_op['status'],
                        configuration=scan_op['configuration']
                    )
                    session2.add(scan)
                    session2.commit()
                    scan_ids.append(scan.id)
                    
            finally:
                session2.close()
                db_manager2.close_session()
            
            # Session 3: Verify scan persistence
            db_manager3 = self.create_db_manager(temp_db_path)
            session3 = db_manager3.get_session()
            
            try:
                # Property: All scans should persist
                recovered_scans = session3.query(Scan).filter(Scan.id.in_(scan_ids)).all()
                assert len(recovered_scans) == len(scan_operations), \
                    f"Should recover {len(scan_operations)} scans, got {len(recovered_scans)}"
                
                # Property: Scan attributes should be preserved
                for i, scan in enumerate(recovered_scans):
                    expected_op = scan_operations[i]
                    assert scan.scan_type == expected_op['scan_type'], "Scan type should persist"
                    assert scan.status == expected_op['status'], "Scan status should persist"
                    assert scan.configuration == expected_op['configuration'], "Scan configuration should persist"
                    assert scan.project_id == project_id, "Scan project association should persist"
                    assert scan.target_id == target_id, "Scan target association should persist"
                
                # Property: Project should maintain scan relationships
                project = session3.query(Project).filter_by(id=project_id).first()
                assert len(project.scans) == len(scan_operations), "Project should maintain all scan relationships"
                
                # Property: Target should maintain scan relationships
                target = session3.query(Target).filter_by(id=target_id).first()
                assert len(target.scans) == len(scan_operations), "Target should maintain all scan relationships"
                
            finally:
                session3.close()
                db_manager3.close_session()
        
        finally:
            # Cleanup temp file
            if os.path.exists(temp_db_path):
                os.unlink(temp_db_path)
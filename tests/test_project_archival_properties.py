"""
Property-based tests for project archival preservation.

Feature: cymind-enhancement, Property 18: Project archival preservation
For any archived project, all associated data should be preserved while 
being marked as inactive and excluded from active operations.
"""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import tempfile
import os
from datetime import datetime, timedelta

from models import Base, Project, Target, Scan, ScanResult, Vulnerability, ProjectStatus, TargetType, ScanType, ScanStatus, ResultType, Severity, DatabaseManager


class TestProjectArchivalPreservation:
    """Test project archival preservation properties"""
    
    def create_temp_db(self):
        """Create temporary database for testing"""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        temp_file.close()
        
        db_url = f'sqlite:///{temp_file.name}'
        db_manager = DatabaseManager(db_url)
        
        return db_manager, temp_file.name
    
    @given(
        project_data=st.fixed_dictionaries({
            'name': st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd'))),
            'description': st.text(max_size=500),
        }),
        targets_data=st.lists(
            st.fixed_dictionaries({
                'name': st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd'))),
                'url': st.text(min_size=5, max_size=50).map(lambda x: f"https://{x}.example.com"),
                'target_type': st.sampled_from([t.value for t in TargetType]),
                'tags': st.lists(st.text(min_size=1, max_size=20), max_size=3)
            }),
            min_size=1, max_size=5
        ),
        scans_per_target=st.integers(min_value=1, max_value=3)
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_project_archival_data_preservation(self, project_data, targets_data, scans_per_target):
        """
        Property 18: Project archival preservation
        Validates: Requirements 5.4
        
        For any project that is archived, all associated data (targets, scans, results) 
        should be preserved exactly as it was before archival.
        """
        temp_db, temp_file = self.create_temp_db()
        session = temp_db.get_session()
        
        try:
            # Create active project with full data hierarchy
            project = Project(
                name=project_data['name'],
                description=project_data['description'],
                status=ProjectStatus.ACTIVE.value
            )
            session.add(project)
            session.commit()
            
            # Create targets
            targets = []
            for target_data in targets_data:
                target = Target(
                    project_id=project.id,
                    name=target_data['name'],
                    url=target_data['url'],
                    target_type=target_data['target_type'],
                    tags=target_data['tags']
                )
                session.add(target)
                targets.append(target)
            
            session.commit()
            
            # Create scans and results for each target
            scans = []
            results = []
            vulnerabilities = []
            
            for target in targets:
                for i in range(scans_per_target):
                    scan = Scan(
                        project_id=project.id,
                        target_id=target.id,
                        scan_type=ScanType.RECON.value,
                        status=ScanStatus.COMPLETED.value,
                        configuration={"test": f"config_{i}"}
                    )
                    session.add(scan)
                    scans.append(scan)
                    
                session.commit()  # Commit scans first to get IDs
                
                # Add scan results
                for scan in scans:
                    for j in range(2):  # 2 results per scan
                        result = ScanResult(
                            scan_id=scan.id,
                            result_type=ResultType.SUBDOMAIN.value,
                            data={"subdomain": f"sub{j}.{scan.target.name}"},
                            severity=Severity.INFO.value,
                            confidence=0.9
                        )
                        session.add(result)
                        results.append(result)
                        
                session.commit()  # Commit results to get IDs
                
                # Add vulnerabilities
                for i, result in enumerate(results):
                    if i % 2 == 0:  # Add vulnerability to every other result
                        vuln = Vulnerability(
                            scan_result_id=result.id,
                            title=f"Test vulnerability for result {result.id}",
                            description="Test vulnerability description",
                            severity=Severity.MEDIUM.value,
                            cvss_score=5.5,
                            affected_service="HTTP"
                        )
                        session.add(vuln)
                        vulnerabilities.append(vuln)
            
            session.commit()
            
            # Capture pre-archival state
            pre_archival_state = {
                'project_id': project.id,
                'project_name': project.name,
                'project_description': project.description,
                'target_count': len(targets),
                'scan_count': len(scans),
                'result_count': len(results),
                'vulnerability_count': len(vulnerabilities),
                'target_names': [t.name for t in targets],
                'scan_types': [s.scan_type for s in scans],
                'result_data': [r.data for r in results],
                'vulnerability_titles': [v.title for v in vulnerabilities]
            }
            
            # Archive the project
            project.status = ProjectStatus.ARCHIVED.value
            session.commit()
            
            # Verify archival preservation
            session.refresh(project)
            
            # Property: Project should be marked as archived
            assert project.status == ProjectStatus.ARCHIVED.value, "Project should be marked as archived"
            
            # Property: All project data should be preserved
            assert project.name == pre_archival_state['project_name'], "Project name should be preserved"
            assert project.description == pre_archival_state['project_description'], "Project description should be preserved"
            
            # Property: All targets should be preserved
            assert len(project.targets) == pre_archival_state['target_count'], \
                f"Should preserve {pre_archival_state['target_count']} targets, got {len(project.targets)}"
            
            preserved_target_names = [t.name for t in project.targets]
            assert set(preserved_target_names) == set(pre_archival_state['target_names']), \
                "All target names should be preserved"
            
            # Property: All scans should be preserved
            assert len(project.scans) == pre_archival_state['scan_count'], \
                f"Should preserve {pre_archival_state['scan_count']} scans, got {len(project.scans)}"
            
            preserved_scan_types = [s.scan_type for s in project.scans]
            # Compare as multisets since order may vary but duplicates matter
            from collections import Counter
            assert Counter(preserved_scan_types) == Counter(pre_archival_state['scan_types']), \
                "All scan types should be preserved"
            
            # Property: All scan results should be preserved
            all_results = []
            for scan in project.scans:
                all_results.extend(scan.results)
            
            assert len(all_results) == pre_archival_state['result_count'], \
                f"Should preserve {pre_archival_state['result_count']} results, got {len(all_results)}"
            
            preserved_result_data = [r.data for r in all_results]
            # Compare as sets since order may vary
            assert len(preserved_result_data) == len(pre_archival_state['result_data']), \
                "All result data should be preserved"
            assert set(str(d) for d in preserved_result_data) == set(str(d) for d in pre_archival_state['result_data']), \
                "All result data should be preserved"
            
            # Property: All vulnerabilities should be preserved
            all_vulnerabilities = []
            for result in all_results:
                all_vulnerabilities.extend(result.vulnerabilities)
            
            assert len(all_vulnerabilities) == pre_archival_state['vulnerability_count'], \
                f"Should preserve {pre_archival_state['vulnerability_count']} vulnerabilities, got {len(all_vulnerabilities)}"
            
            preserved_vuln_titles = [v.title for v in all_vulnerabilities]
            # Compare as sets since order may vary
            assert len(preserved_vuln_titles) == len(pre_archival_state['vulnerability_titles']), \
                "All vulnerability titles should be preserved"
            assert set(preserved_vuln_titles) == set(pre_archival_state['vulnerability_titles']), \
                "All vulnerability titles should be preserved"
        
        finally:
            session.close()
            temp_db.close_session()
            os.unlink(temp_file)
    
    @given(
        active_projects=st.lists(
            st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd'))),
            min_size=2, max_size=5, unique=True
        ),
        archived_projects=st.lists(
            st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd'))),
            min_size=1, max_size=3, unique=True
        )
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_archived_project_exclusion_from_active_operations(self, active_projects, archived_projects):
        """
        Property 18: Project archival preservation (exclusion from active operations)
        Validates: Requirements 5.4
        
        For any archived projects, they should be excluded from active operations 
        while remaining accessible for historical queries.
        """
        temp_db, temp_file = self.create_temp_db()
        session = temp_db.get_session()
        
        try:
            # Ensure no name conflicts between active and archived
            all_names = set(active_projects + archived_projects)
            if len(all_names) != len(active_projects) + len(archived_projects):
                # Skip if there are name conflicts
                return
            
            # Create active projects
            active_project_objects = []
            for name in active_projects:
                project = Project(
                    name=name,
                    description=f"Active project {name}",
                    status=ProjectStatus.ACTIVE.value
                )
                session.add(project)
                active_project_objects.append(project)
            
            # Create archived projects
            archived_project_objects = []
            for name in archived_projects:
                project = Project(
                    name=name,
                    description=f"Archived project {name}",
                    status=ProjectStatus.ARCHIVED.value
                )
                session.add(project)
                archived_project_objects.append(project)
            
            session.commit()
            
            # Property: Active project queries should exclude archived projects
            active_query_results = session.query(Project).filter_by(status=ProjectStatus.ACTIVE.value).all()
            active_names_from_query = {p.name for p in active_query_results}
            expected_active_names = set(active_projects)
            
            assert active_names_from_query == expected_active_names, \
                f"Active project query should return only active projects. Expected: {expected_active_names}, Got: {active_names_from_query}"
            
            # Property: Archived projects should not appear in active queries
            for archived_project in archived_project_objects:
                assert archived_project not in active_query_results, \
                    f"Archived project {archived_project.name} should not appear in active project queries"
            
            # Property: Archived projects should be accessible via direct queries
            archived_query_results = session.query(Project).filter_by(status=ProjectStatus.ARCHIVED.value).all()
            archived_names_from_query = {p.name for p in archived_query_results}
            expected_archived_names = set(archived_projects)
            
            assert archived_names_from_query == expected_archived_names, \
                f"Archived project query should return only archived projects. Expected: {expected_archived_names}, Got: {archived_names_from_query}"
            
            # Property: All projects should be accessible via unrestricted queries
            all_query_results = session.query(Project).all()
            all_names_from_query = {p.name for p in all_query_results}
            expected_all_names = set(active_projects + archived_projects)
            
            assert all_names_from_query == expected_all_names, \
                f"Unrestricted query should return all projects. Expected: {expected_all_names}, Got: {all_names_from_query}"
        
        finally:
            session.close()
            temp_db.close_session()
            os.unlink(temp_file)
    
    @given(
        project_name=st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd'))),
        archival_operations=st.lists(
            st.one_of(
                st.just("archive"),
                st.just("restore"),
                st.just("re_archive")
            ),
            min_size=1, max_size=10
        )
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_project_archival_state_transitions(self, project_name, archival_operations):
        """
        Property 18: Project archival preservation (state transitions)
        Validates: Requirements 5.4
        
        For any sequence of archival operations, project state should transition 
        correctly while preserving all data throughout the transitions.
        """
        temp_db, temp_file = self.create_temp_db()
        session = temp_db.get_session()
        
        try:
            # Create project with some data
            project = Project(
                name=project_name,
                description="Test project for archival transitions",
                status=ProjectStatus.ACTIVE.value
            )
            session.add(project)
            session.commit()
            
            # Add target and scan for data preservation testing
            target = Target(
                project_id=project.id,
                name="test_target",
                url="https://test.example.com",
                target_type=TargetType.DOMAIN.value
            )
            session.add(target)
            session.commit()
            
            scan = Scan(
                project_id=project.id,
                target_id=target.id,
                scan_type=ScanType.RECON.value,
                status=ScanStatus.COMPLETED.value
            )
            session.add(scan)
            session.commit()
            
            # Capture initial data state
            initial_target_count = len(project.targets)
            initial_scan_count = len(project.scans)
            
            # Apply archival operations
            current_status = ProjectStatus.ACTIVE.value
            
            for operation in archival_operations:
                if operation == "archive" and current_status == ProjectStatus.ACTIVE.value:
                    project.status = ProjectStatus.ARCHIVED.value
                    current_status = ProjectStatus.ARCHIVED.value
                elif operation == "restore" and current_status == ProjectStatus.ARCHIVED.value:
                    project.status = ProjectStatus.ACTIVE.value
                    current_status = ProjectStatus.ACTIVE.value
                elif operation == "re_archive" and current_status == ProjectStatus.ACTIVE.value:
                    project.status = ProjectStatus.ARCHIVED.value
                    current_status = ProjectStatus.ARCHIVED.value
                
                session.commit()
                session.refresh(project)
                
                # Property: Data should be preserved through all transitions
                assert len(project.targets) == initial_target_count, \
                    f"Target count should remain {initial_target_count} after {operation}, got {len(project.targets)}"
                assert len(project.scans) == initial_scan_count, \
                    f"Scan count should remain {initial_scan_count} after {operation}, got {len(project.scans)}"
                
                # Property: Status should reflect the operation
                assert project.status == current_status, \
                    f"Project status should be {current_status} after {operation}, got {project.status}"
                
                # Property: Relationships should remain intact
                for target in project.targets:
                    assert target.project_id == project.id, \
                        f"Target project relationship should remain intact after {operation}"
                
                for scan in project.scans:
                    assert scan.project_id == project.id, \
                        f"Scan project relationship should remain intact after {operation}"
                    assert scan.target_id == target.id, \
                        f"Scan target relationship should remain intact after {operation}"
        
        finally:
            session.close()
            temp_db.close_session()
            os.unlink(temp_file)
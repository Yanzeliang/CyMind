"""
Property-based tests for project organization integrity.

Feature: cymind-enhancement, Property 16: Project organization integrity
For any created project, targets and scans should be properly grouped and 
associated without cross-contamination between projects.
"""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import tempfile
import os

from models import Base, Project, Target, Scan, ProjectStatus, TargetType, ScanType, ScanStatus, DatabaseManager, DataValidator


class TestProjectOrganizationIntegrity:
    """Test project organization integrity properties"""
    
    def create_temp_db(self):
        """Create temporary database for testing"""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        temp_file.close()
        
        db_url = f'sqlite:///{temp_file.name}'
        db_manager = DatabaseManager(db_url)
        
        return db_manager, temp_file.name
    
    @given(
        project_names=st.lists(
            st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd'))),
            min_size=2, max_size=5, unique=True
        ),
        target_names=st.lists(
            st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd'))),
            min_size=1, max_size=10
        )
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_project_target_association_integrity(self, project_names, target_names):
        """
        Property 16: Project organization integrity
        Validates: Requirements 5.1, 5.3
        
        For any created projects and targets, each target should be associated 
        with exactly one project and targets should not cross-contaminate between projects.
        """
        temp_db, temp_file = self.create_temp_db()
        session = temp_db.get_session()
        
        try:
            # Create projects
            projects = []
            for name in project_names:
                project = Project(
                    name=name,
                    description=f"Test project {name}",
                    status=ProjectStatus.ACTIVE.value
                )
                session.add(project)
                projects.append(project)
            
            session.commit()
            
            # Create targets and associate with projects
            targets_by_project = {}
            for i, target_name in enumerate(target_names):
                project = projects[i % len(projects)]  # Distribute targets across projects
                
                target = Target(
                    project_id=project.id,
                    name=target_name,
                    url=f"https://{target_name}.example.com",
                    target_type=TargetType.DOMAIN.value,
                    target_metadata={"test": True}
                )
                session.add(target)
                
                if project.id not in targets_by_project:
                    targets_by_project[project.id] = []
                targets_by_project[project.id].append(target)
            
            session.commit()
            
            # Verify project organization integrity
            for project in projects:
                # Refresh project to get relationships
                session.refresh(project)
                
                # Property: Each project should have its assigned targets
                expected_target_count = len(targets_by_project.get(project.id, []))
                actual_target_count = len(project.targets)
                assert actual_target_count == expected_target_count, \
                    f"Project {project.name} should have {expected_target_count} targets, got {actual_target_count}"
                
                # Property: All targets in project should reference the correct project
                for target in project.targets:
                    assert target.project_id == project.id, \
                        f"Target {target.name} should belong to project {project.id}, got {target.project_id}"
                
                # Property: No target should appear in multiple projects
                for other_project in projects:
                    if other_project.id != project.id:
                        session.refresh(other_project)
                        project_target_ids = {t.id for t in project.targets}
                        other_target_ids = {t.id for t in other_project.targets}
                        overlap = project_target_ids.intersection(other_target_ids)
                        assert len(overlap) == 0, \
                            f"Projects {project.id} and {other_project.id} should not share targets, found overlap: {overlap}"
        
        finally:
            session.close()
            temp_db.close_session()
            os.unlink(temp_file)
    
    @given(
        project_data=st.fixed_dictionaries({
            'name': st.text(min_size=1, max_size=100),
            'description': st.text(max_size=500),
            'status': st.sampled_from([s.value for s in ProjectStatus])
        }),
        scan_configs=st.lists(
            st.fixed_dictionaries({
                'scan_type': st.sampled_from([s.value for s in ScanType]),
                'configuration': st.dictionaries(st.text(max_size=20), st.text(max_size=50), max_size=3)
            }),
            min_size=1, max_size=5
        )
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_project_scan_association_integrity(self, project_data, scan_configs):
        """
        Property 16: Project organization integrity (scan association)
        Validates: Requirements 5.1, 5.3
        
        For any project with scans, all scans should be properly associated 
        and isolated within their project boundaries.
        """
        temp_db, temp_file = self.create_temp_db()
        session = temp_db.get_session()
        
        try:
            # Validate project data first
            validation_errors = DataValidator.validate_project(project_data)
            if validation_errors:
                # Skip invalid data - this tests our validation works
                return
            
            # Create project
            project = Project(**project_data)
            session.add(project)
            session.commit()
            
            # Create target for scans
            target = Target(
                project_id=project.id,
                name="test-target",
                url="https://test.example.com",
                target_type=TargetType.DOMAIN.value
            )
            session.add(target)
            session.commit()
            
            # Create scans
            scans = []
            for scan_config in scan_configs:
                scan = Scan(
                    project_id=project.id,
                    target_id=target.id,
                    scan_type=scan_config['scan_type'],
                    status=ScanStatus.PENDING.value,
                    configuration=scan_config['configuration']
                )
                session.add(scan)
                scans.append(scan)
            
            session.commit()
            
            # Verify scan organization integrity
            session.refresh(project)
            
            # Property: Project should contain all its scans
            assert len(project.scans) == len(scans), \
                f"Project should have {len(scans)} scans, got {len(project.scans)}"
            
            # Property: All scans should reference the correct project and target
            for scan in project.scans:
                assert scan.project_id == project.id, \
                    f"Scan should belong to project {project.id}, got {scan.project_id}"
                assert scan.target_id == target.id, \
                    f"Scan should belong to target {target.id}, got {scan.target_id}"
            
            # Property: Target should contain all scans
            session.refresh(target)
            assert len(target.scans) == len(scans), \
                f"Target should have {len(scans)} scans, got {len(target.scans)}"
        
        finally:
            session.close()
            temp_db.close_session()
            os.unlink(temp_file)
    
    @given(
        num_projects=st.integers(min_value=2, max_value=5),
        operations=st.lists(
            st.one_of(
                st.tuples(st.just("create_target"), st.integers(min_value=0, max_value=4)),
                st.tuples(st.just("create_scan"), st.integers(min_value=0, max_value=4))
            ),
            min_size=5, max_size=20
        )
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_cross_project_contamination_prevention(self, num_projects, operations):
        """
        Property 16: Project organization integrity (contamination prevention)
        Validates: Requirements 5.1, 5.3
        
        For any sequence of operations across multiple projects, there should be 
        no cross-contamination of data between projects.
        """
        temp_db, temp_file = self.create_temp_db()
        session = temp_db.get_session()
        
        try:
            # Create multiple projects
            projects = []
            for i in range(num_projects):
                project = Project(
                    name=f"project_{i}",
                    description=f"Test project {i}",
                    status=ProjectStatus.ACTIVE.value
                )
                session.add(project)
                projects.append(project)
            
            session.commit()
            
            # Create initial targets for each project
            targets_by_project = {}
            for project in projects:
                target = Target(
                    project_id=project.id,
                    name=f"target_for_project_{project.id}",
                    url=f"https://project{project.id}.example.com",
                    target_type=TargetType.DOMAIN.value
                )
                session.add(target)
                targets_by_project[project.id] = [target]
            
            session.commit()
            
            # Execute operations
            for operation, project_idx in operations:
                if project_idx >= len(projects):
                    continue
                
                project = projects[project_idx]
                
                if operation == "create_target":
                    target = Target(
                        project_id=project.id,
                        name=f"target_{len(targets_by_project[project.id])}",
                        url=f"https://target{len(targets_by_project[project.id])}.example.com",
                        target_type=TargetType.DOMAIN.value
                    )
                    session.add(target)
                    targets_by_project[project.id].append(target)
                
                elif operation == "create_scan" and targets_by_project[project.id]:
                    target = targets_by_project[project.id][0]  # Use first target
                    scan = Scan(
                        project_id=project.id,
                        target_id=target.id,
                        scan_type=ScanType.RECON.value,
                        status=ScanStatus.PENDING.value
                    )
                    session.add(scan)
            
            session.commit()
            
            # Verify no cross-contamination
            for i, project in enumerate(projects):
                session.refresh(project)
                
                # Property: All targets belong to correct project
                for target in project.targets:
                    assert target.project_id == project.id, \
                        f"Target contamination: target {target.id} in project {project.id} has project_id {target.project_id}"
                
                # Property: All scans belong to correct project
                for scan in project.scans:
                    assert scan.project_id == project.id, \
                        f"Scan contamination: scan {scan.id} in project {project.id} has project_id {scan.project_id}"
                    
                    # Property: Scan target belongs to same project
                    assert scan.target.project_id == project.id, \
                        f"Cross-project scan: scan {scan.id} in project {project.id} references target in project {scan.target.project_id}"
                
                # Property: No data from other projects
                for j, other_project in enumerate(projects):
                    if i != j:
                        session.refresh(other_project)
                        
                        # Check no shared targets
                        project_target_ids = {t.id for t in project.targets}
                        other_target_ids = {t.id for t in other_project.targets}
                        assert project_target_ids.isdisjoint(other_target_ids), \
                            f"Projects {project.id} and {other_project.id} share targets"
                        
                        # Check no shared scans
                        project_scan_ids = {s.id for s in project.scans}
                        other_scan_ids = {s.id for s in other_project.scans}
                        assert project_scan_ids.isdisjoint(other_scan_ids), \
                            f"Projects {project.id} and {other_project.id} share scans"
        
        finally:
            session.close()
            temp_db.close_session()
            os.unlink(temp_file)
"""
CyMind Project Manager Module
Enhanced project management with organization, archival, and multi-user support
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import joinedload

from models import (
    Session, Project, Target, Scan, ScanResult, 
    ProjectStatus, DataValidator, db_manager
)
from core.error_handler import error_handler_decorator, get_error_handler
from core.logging_config import get_logger

logger = get_logger("cymind.project_manager")
error_handler = get_error_handler()


class ProjectManager:
    """Enhanced project management with organization and archival capabilities"""
    
    def __init__(self):
        self.validator = DataValidator()
    
    @error_handler_decorator(error_handler)
    def create_project(self, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new project with validation
        
        Args:
            project_data: Dictionary containing project information
                - name (required): Project name
                - description (optional): Project description
                - status (optional): Project status (defaults to 'active')
        
        Returns:
            Dictionary with project information or error details
        """
        logger.info(f"Creating new project: {project_data.get('name', 'Unknown')}")
        
        # Validate project data
        validation_errors = self.validator.validate_project(project_data)
        if validation_errors:
            logger.warning(f"Project validation failed: {validation_errors}")
            return {
                "status": "error",
                "message": "Validation failed",
                "errors": validation_errors
            }
        
        session = Session()
        try:
            # Check for duplicate project names
            existing_project = session.query(Project).filter_by(
                name=project_data['name']
            ).first()
            
            if existing_project:
                logger.warning(f"Project name already exists: {project_data['name']}")
                return {
                    "status": "error",
                    "message": f"Project '{project_data['name']}' already exists"
                }
            
            # Create new project
            project = Project(
                name=project_data['name'],
                description=project_data.get('description', ''),
                status=project_data.get('status', ProjectStatus.ACTIVE.value)
            )
            
            session.add(project)
            session.commit()
            session.refresh(project)
            
            logger.info(f"Project created successfully: ID={project.id}, Name={project.name}")
            
            return {
                "status": "success",
                "project": {
                    "id": project.id,
                    "name": project.name,
                    "description": project.description,
                    "status": project.status,
                    "created_at": project.created_at.isoformat(),
                    "target_count": 0,
                    "scan_count": 0
                }
            }
            
        except IntegrityError as e:
            session.rollback()
            logger.error(f"Database integrity error creating project: {e}")
            return {
                "status": "error",
                "message": "Project name must be unique"
            }
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error creating project: {e}")
            return {
                "status": "error",
                "message": "Database error occurred"
            }
        finally:
            session.close()
    
    @error_handler_decorator(error_handler)
    def get_projects(self, include_archived: bool = False) -> List[Dict[str, Any]]:
        """
        Get list of projects with statistics
        
        Args:
            include_archived: Whether to include archived projects
        
        Returns:
            List of project dictionaries with statistics
        """
        logger.debug(f"Retrieving projects (include_archived={include_archived})")
        
        session = Session()
        try:
            query = session.query(Project).options(
                joinedload(Project.targets),
                joinedload(Project.scans)
            )
            
            if not include_archived:
                query = query.filter(Project.status != ProjectStatus.ARCHIVED.value)
            
            projects = query.order_by(Project.updated_at.desc()).all()
            
            project_list = []
            for project in projects:
                project_dict = {
                    "id": project.id,
                    "name": project.name,
                    "description": project.description,
                    "status": project.status,
                    "created_at": project.created_at.isoformat(),
                    "updated_at": project.updated_at.isoformat(),
                    "target_count": len(project.targets),
                    "scan_count": len(project.scans),
                    "active_scans": len([s for s in project.scans if s.status == 'running']),
                    "completed_scans": len([s for s in project.scans if s.status == 'completed'])
                }
                project_list.append(project_dict)
            
            logger.debug(f"Retrieved {len(project_list)} projects")
            return project_list
            
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving projects: {e}")
            return []
        finally:
            session.close()
    
    @error_handler_decorator(error_handler)
    def get_project(self, project_id: int) -> Optional[Dict[str, Any]]:
        """
        Get detailed project information
        
        Args:
            project_id: Project ID
        
        Returns:
            Project dictionary with detailed information or None
        """
        logger.debug(f"Retrieving project details: ID={project_id}")
        
        session = Session()
        try:
            project = session.query(Project).options(
                joinedload(Project.targets),
                joinedload(Project.scans).joinedload(Scan.results)
            ).filter_by(id=project_id).first()
            
            if not project:
                logger.warning(f"Project not found: ID={project_id}")
                return None
            
            # Calculate statistics
            total_vulnerabilities = 0
            high_severity_vulns = 0
            
            for scan in project.scans:
                for result in scan.results:
                    if result.result_type == 'vulnerability':
                        total_vulnerabilities += 1
                        if result.severity in ['high', 'critical']:
                            high_severity_vulns += 1
            
            project_dict = {
                "id": project.id,
                "name": project.name,
                "description": project.description,
                "status": project.status,
                "created_at": project.created_at.isoformat(),
                "updated_at": project.updated_at.isoformat(),
                "targets": [
                    {
                        "id": target.id,
                        "name": target.name,
                        "url": target.url,
                        "ip_address": target.ip_address,
                        "target_type": target.target_type,
                        "created_at": target.created_at.isoformat(),
                        "tags": target.tags or []
                    }
                    for target in project.targets
                ],
                "scans": [
                    {
                        "id": scan.id,
                        "target_id": scan.target_id,
                        "scan_type": scan.scan_type,
                        "status": scan.status,
                        "started_at": scan.started_at.isoformat(),
                        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                        "result_count": len(scan.results)
                    }
                    for scan in project.scans
                ],
                "statistics": {
                    "target_count": len(project.targets),
                    "scan_count": len(project.scans),
                    "active_scans": len([s for s in project.scans if s.status == 'running']),
                    "completed_scans": len([s for s in project.scans if s.status == 'completed']),
                    "total_vulnerabilities": total_vulnerabilities,
                    "high_severity_vulnerabilities": high_severity_vulns
                }
            }
            
            logger.debug(f"Retrieved project details: {project.name}")
            return project_dict
            
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving project: {e}")
            return None
        finally:
            session.close()
    
    @error_handler_decorator(error_handler)
    def update_project(self, project_id: int, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update project information
        
        Args:
            project_id: Project ID
            update_data: Dictionary containing fields to update
        
        Returns:
            Dictionary with update status and project information
        """
        logger.info(f"Updating project: ID={project_id}")
        
        # Validate update data
        validation_errors = self.validator.validate_project(update_data)
        if validation_errors:
            logger.warning(f"Project update validation failed: {validation_errors}")
            return {
                "status": "error",
                "message": "Validation failed",
                "errors": validation_errors
            }
        
        session = Session()
        try:
            project = session.query(Project).filter_by(id=project_id).first()
            
            if not project:
                logger.warning(f"Project not found for update: ID={project_id}")
                return {
                    "status": "error",
                    "message": "Project not found"
                }
            
            # Check for name conflicts if name is being updated
            if 'name' in update_data and update_data['name'] != project.name:
                existing_project = session.query(Project).filter_by(
                    name=update_data['name']
                ).first()
                
                if existing_project:
                    logger.warning(f"Project name conflict during update: {update_data['name']}")
                    return {
                        "status": "error",
                        "message": f"Project '{update_data['name']}' already exists"
                    }
            
            # Update project fields
            for field, value in update_data.items():
                if hasattr(project, field):
                    setattr(project, field, value)
            
            project.updated_at = datetime.now()
            session.commit()
            session.refresh(project)
            
            logger.info(f"Project updated successfully: ID={project.id}")
            
            return {
                "status": "success",
                "project": {
                    "id": project.id,
                    "name": project.name,
                    "description": project.description,
                    "status": project.status,
                    "updated_at": project.updated_at.isoformat()
                }
            }
            
        except IntegrityError as e:
            session.rollback()
            logger.error(f"Database integrity error updating project: {e}")
            return {
                "status": "error",
                "message": "Project name must be unique"
            }
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error updating project: {e}")
            return {
                "status": "error",
                "message": "Database error occurred"
            }
        finally:
            session.close()
    
    @error_handler_decorator(error_handler)
    def archive_project(self, project_id: int) -> Dict[str, Any]:
        """
        Archive a project (soft delete)
        
        Args:
            project_id: Project ID
        
        Returns:
            Dictionary with archive status
        """
        logger.info(f"Archiving project: ID={project_id}")
        
        session = Session()
        try:
            project = session.query(Project).filter_by(id=project_id).first()
            
            if not project:
                logger.warning(f"Project not found for archival: ID={project_id}")
                return {
                    "status": "error",
                    "message": "Project not found"
                }
            
            if project.status == ProjectStatus.ARCHIVED.value:
                logger.info(f"Project already archived: ID={project_id}")
                return {
                    "status": "success",
                    "message": "Project is already archived"
                }
            
            # Archive the project
            project.status = ProjectStatus.ARCHIVED.value
            project.updated_at = datetime.now()
            session.commit()
            
            logger.info(f"Project archived successfully: ID={project_id}")
            
            return {
                "status": "success",
                "message": f"Project '{project.name}' has been archived"
            }
            
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error archiving project: {e}")
            return {
                "status": "error",
                "message": "Database error occurred"
            }
        finally:
            session.close()
    
    @error_handler_decorator(error_handler)
    def restore_project(self, project_id: int) -> Dict[str, Any]:
        """
        Restore an archived project
        
        Args:
            project_id: Project ID
        
        Returns:
            Dictionary with restore status
        """
        logger.info(f"Restoring project: ID={project_id}")
        
        session = Session()
        try:
            project = session.query(Project).filter_by(id=project_id).first()
            
            if not project:
                logger.warning(f"Project not found for restoration: ID={project_id}")
                return {
                    "status": "error",
                    "message": "Project not found"
                }
            
            if project.status != ProjectStatus.ARCHIVED.value:
                logger.info(f"Project is not archived: ID={project_id}")
                return {
                    "status": "success",
                    "message": "Project is not archived"
                }
            
            # Restore the project
            project.status = ProjectStatus.ACTIVE.value
            project.updated_at = datetime.now()
            session.commit()
            
            logger.info(f"Project restored successfully: ID={project_id}")
            
            return {
                "status": "success",
                "message": f"Project '{project.name}' has been restored"
            }
            
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error restoring project: {e}")
            return {
                "status": "error",
                "message": "Database error occurred"
            }
        finally:
            session.close()
    
    @error_handler_decorator(error_handler)
    def delete_project(self, project_id: int, force: bool = False) -> Dict[str, Any]:
        """
        Delete a project permanently
        
        Args:
            project_id: Project ID
            force: Whether to force delete even with associated data
        
        Returns:
            Dictionary with deletion status
        """
        logger.warning(f"Attempting to delete project: ID={project_id}, force={force}")
        
        session = Session()
        try:
            project = session.query(Project).filter_by(id=project_id).first()
            
            if not project:
                logger.warning(f"Project not found for deletion: ID={project_id}")
                return {
                    "status": "error",
                    "message": "Project not found"
                }
            
            # Check for associated data
            target_count = len(project.targets)
            scan_count = len(project.scans)
            
            if (target_count > 0 or scan_count > 0) and not force:
                logger.warning(f"Project has associated data: targets={target_count}, scans={scan_count}")
                return {
                    "status": "error",
                    "message": f"Project has {target_count} targets and {scan_count} scans. Use force=True to delete anyway."
                }
            
            project_name = project.name
            session.delete(project)
            session.commit()
            
            logger.warning(f"Project deleted permanently: {project_name}")
            
            return {
                "status": "success",
                "message": f"Project '{project_name}' has been deleted permanently"
            }
            
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error deleting project: {e}")
            return {
                "status": "error",
                "message": "Database error occurred"
            }
        finally:
            session.close()
    
    @error_handler_decorator(error_handler)
    def associate_target_to_project(self, target_id: int, project_id: int) -> Dict[str, Any]:
        """
        Associate a target with a project
        
        Args:
            target_id: Target ID
            project_id: Project ID
        
        Returns:
            Dictionary with association status
        """
        logger.info(f"Associating target {target_id} to project {project_id}")
        
        session = Session()
        try:
            # Verify both target and project exist
            target = session.query(Target).filter_by(id=target_id).first()
            project = session.query(Project).filter_by(id=project_id).first()
            
            if not target:
                logger.warning(f"Target not found: ID={target_id}")
                return {
                    "status": "error",
                    "message": "Target not found"
                }
            
            if not project:
                logger.warning(f"Project not found: ID={project_id}")
                return {
                    "status": "error",
                    "message": "Project not found"
                }
            
            # Update target's project association
            target.project_id = project_id
            project.updated_at = datetime.now()
            session.commit()
            
            logger.info(f"Target associated successfully: target={target.name}, project={project.name}")
            
            return {
                "status": "success",
                "message": f"Target '{target.name}' associated with project '{project.name}'"
            }
            
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error associating target to project: {e}")
            return {
                "status": "error",
                "message": "Database error occurred"
            }
        finally:
            session.close()
    
    @error_handler_decorator(error_handler)
    def get_project_statistics(self) -> Dict[str, Any]:
        """
        Get overall project statistics
        
        Returns:
            Dictionary with project statistics
        """
        logger.debug("Retrieving project statistics")
        
        session = Session()
        try:
            total_projects = session.query(Project).count()
            active_projects = session.query(Project).filter_by(
                status=ProjectStatus.ACTIVE.value
            ).count()
            archived_projects = session.query(Project).filter_by(
                status=ProjectStatus.ARCHIVED.value
            ).count()
            
            # Get projects with most targets and scans
            projects_with_stats = session.query(Project).options(
                joinedload(Project.targets),
                joinedload(Project.scans)
            ).all()
            
            most_targets = max(projects_with_stats, 
                             key=lambda p: len(p.targets), 
                             default=None)
            most_scans = max(projects_with_stats, 
                           key=lambda p: len(p.scans), 
                           default=None)
            
            statistics = {
                "total_projects": total_projects,
                "active_projects": active_projects,
                "archived_projects": archived_projects,
                "most_targets_project": {
                    "name": most_targets.name if most_targets else None,
                    "target_count": len(most_targets.targets) if most_targets else 0
                },
                "most_scans_project": {
                    "name": most_scans.name if most_scans else None,
                    "scan_count": len(most_scans.scans) if most_scans else 0
                }
            }
            
            logger.debug(f"Project statistics: {statistics}")
            return statistics
            
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving project statistics: {e}")
            return {
                "total_projects": 0,
                "active_projects": 0,
                "archived_projects": 0,
                "most_targets_project": {"name": None, "target_count": 0},
                "most_scans_project": {"name": None, "scan_count": 0}
            }
        finally:
            session.close()
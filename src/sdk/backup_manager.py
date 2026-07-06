"""
Database Backup Manager

Automatic backup rotation with health checks and recovery.
Keeps only the last N backups to save disk space.
"""

import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict
from dataclasses import dataclass
from loguru import logger


@dataclass
class BackupInfo:
    """Information about a backup."""
    path: Path
    timestamp: datetime
    size_bytes: int
    is_valid: bool
    
    def age_hours(self) -> float:
        """Get backup age in hours."""
        return (datetime.now() - self.timestamp).total_seconds() / 3600
    
    def size_mb(self) -> float:
        """Get backup size in MB."""
        return self.size_bytes / (1024 * 1024)


class BackupManager:
    """
    Manages automatic backups with rotation and health checks.
    """
    
    def __init__(
        self,
        source_dir: Path,
        backup_base_dir: Path,
        max_backups: int = 3,
        backup_interval_hours: int = 24
    ):
        """
        Initialize backup manager.
        
        Args:
            source_dir: Directory to backup
            backup_base_dir: Base directory for backups
            max_backups: Maximum number of backups to keep
            backup_interval_hours: Minimum hours between backups
        """
        self.source_dir = Path(source_dir)
        self.backup_base_dir = Path(backup_base_dir)
        self.max_backups = max_backups
        self.backup_interval_hours = backup_interval_hours
        
        self.backup_base_dir.mkdir(parents=True, exist_ok=True)
    
    def should_backup(self) -> bool:
        """Check if a new backup should be created."""
        if not self.source_dir.exists():
            return False
        
        backups = self.list_backups()
        if not backups:
            return True
        
        # Check if enough time has passed since last backup
        latest = backups[0]
        return latest.age_hours() >= self.backup_interval_hours
    
    def create_backup(self, force: bool = False) -> Optional[BackupInfo]:
        """
        Create a new backup.
        
        Args:
            force: Create backup even if interval hasn't passed
        
        Returns:
            BackupInfo if backup was created, None otherwise
        """
        if not force and not self.should_backup():
            logger.debug("Backup not needed yet")
            return None
        
        if not self.source_dir.exists():
            logger.warning(f"Source directory does not exist: {self.source_dir}")
            return None
        
        # Generate backup name with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{self.source_dir.name}_backup_{timestamp}"
        backup_path = self.backup_base_dir / backup_name
        
        try:
            logger.info(f"Creating backup: {backup_path}")
            
            # Copy directory
            shutil.copytree(self.source_dir, backup_path)
            
            # Get backup info
            size = sum(f.stat().st_size for f in backup_path.rglob('*') if f.is_file())
            
            backup_info = BackupInfo(
                path=backup_path,
                timestamp=datetime.now(),
                size_bytes=size,
                is_valid=self._validate_backup(backup_path)
            )
            
            logger.info(
                f"Backup created successfully: {backup_path.name} "
                f"({backup_info.size_mb():.2f} MB)"
            )
            
            # Rotate old backups
            self.rotate_backups()
            
            return backup_info
            
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            # Clean up partial backup
            if backup_path.exists():
                try:
                    shutil.rmtree(backup_path)
                except:
                    pass
            return None
    
    def list_backups(self) -> List[BackupInfo]:
        """
        List all backups, sorted by timestamp (newest first).
        
        Returns:
            List of BackupInfo objects
        """
        backups = []
        
        if not self.backup_base_dir.exists():
            return backups
        
        # Find all backup directories
        pattern = f"{self.source_dir.name}_backup_*"
        for backup_dir in self.backup_base_dir.glob(pattern):
            if not backup_dir.is_dir():
                continue
            
            try:
                # Extract timestamp from directory name
                timestamp_str = backup_dir.name.split('_backup_')[-1]
                timestamp = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                
                # Calculate size
                size = sum(f.stat().st_size for f in backup_dir.rglob('*') if f.is_file())
                
                # Validate backup
                is_valid = self._validate_backup(backup_dir)
                
                backups.append(BackupInfo(
                    path=backup_dir,
                    timestamp=timestamp,
                    size_bytes=size,
                    is_valid=is_valid
                ))
            except Exception as e:
                logger.warning(f"Failed to process backup {backup_dir}: {e}")
        
        # Sort by timestamp (newest first)
        backups.sort(key=lambda b: b.timestamp, reverse=True)
        
        return backups
    
    def rotate_backups(self):
        """Remove old backups, keeping only the most recent N."""
        backups = self.list_backups()
        
        if len(backups) <= self.max_backups:
            return
        
        # Remove oldest backups
        to_remove = backups[self.max_backups:]
        
        for backup in to_remove:
            try:
                logger.info(f"Removing old backup: {backup.path.name}")
                shutil.rmtree(backup.path)
            except Exception as e:
                logger.error(f"Failed to remove backup {backup.path}: {e}")
    
    def restore_backup(self, backup_info: Optional[BackupInfo] = None) -> bool:
        """
        Restore from a backup.
        
        Args:
            backup_info: Specific backup to restore, or None for latest
        
        Returns:
            True if restore was successful
        """
        if backup_info is None:
            backups = self.list_backups()
            if not backups:
                logger.error("No backups available to restore")
                return False
            backup_info = backups[0]
        
        if not backup_info.is_valid:
            logger.error(f"Backup is not valid: {backup_info.path}")
            return False
        
        try:
            logger.info(f"Restoring from backup: {backup_info.path.name}")
            
            # Backup current state before restoring
            if self.source_dir.exists():
                temp_backup = self.source_dir.parent / f"{self.source_dir.name}_temp_backup"
                if temp_backup.exists():
                    shutil.rmtree(temp_backup)
                shutil.move(str(self.source_dir), str(temp_backup))
            
            # Restore from backup
            shutil.copytree(backup_info.path, self.source_dir)
            
            logger.info("Backup restored successfully")
            
            # Remove temp backup if restore was successful
            if temp_backup.exists():
                shutil.rmtree(temp_backup)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore backup: {e}")
            
            # Try to restore temp backup
            if temp_backup.exists():
                try:
                    if self.source_dir.exists():
                        shutil.rmtree(self.source_dir)
                    shutil.move(str(temp_backup), str(self.source_dir))
                    logger.info("Restored original state after failed restore")
                except:
                    logger.critical("Failed to restore original state!")
            
            return False
    
    def _validate_backup(self, backup_path: Path) -> bool:
        """
        Validate a backup directory.
        
        Args:
            backup_path: Path to backup directory
        
        Returns:
            True if backup appears valid
        """
        if not backup_path.exists() or not backup_path.is_dir():
            return False
        
        # Check if backup has any files
        files = list(backup_path.rglob('*'))
        if not files:
            return False
        
        # For ChromaDB backups, check for essential files
        if (backup_path / "chroma.sqlite3").exists():
            # Valid ChromaDB backup
            return True
        
        # For general backups, just check it's not empty
        return len(files) > 0
    
    def health_check(self) -> Dict:
        """
        Perform health check on backups.
        
        Returns:
            Dict with health check results
        """
        backups = self.list_backups()
        
        total_size = sum(b.size_bytes for b in backups)
        valid_backups = [b for b in backups if b.is_valid]
        invalid_backups = [b for b in backups if not b.is_valid]
        
        oldest_backup = backups[-1] if backups else None
        newest_backup = backups[0] if backups else None
        
        return {
            'total_backups': len(backups),
            'valid_backups': len(valid_backups),
            'invalid_backups': len(invalid_backups),
            'total_size_mb': total_size / (1024 * 1024),
            'oldest_backup_age_hours': oldest_backup.age_hours() if oldest_backup else None,
            'newest_backup_age_hours': newest_backup.age_hours() if newest_backup else None,
            'backup_list': [
                {
                    'name': b.path.name,
                    'age_hours': b.age_hours(),
                    'size_mb': b.size_mb(),
                    'valid': b.is_valid
                }
                for b in backups
            ]
        }
    
    def cleanup_invalid_backups(self):
        """Remove all invalid backups."""
        backups = self.list_backups()
        invalid = [b for b in backups if not b.is_valid]
        
        for backup in invalid:
            try:
                logger.info(f"Removing invalid backup: {backup.path.name}")
                shutil.rmtree(backup.path)
            except Exception as e:
                logger.error(f"Failed to remove invalid backup: {e}")


def auto_backup_memory(force: bool = False) -> Optional[BackupInfo]:
    """
    Convenience function to backup the memory directory.
    
    Args:
        force: Force backup even if interval hasn't passed
    
    Returns:
        BackupInfo if backup was created
    """
    from .config import get_config
    
    config = get_config()
    
    if not config.memory.auto_backup:
        return None
    
    manager = BackupManager(
        source_dir=Path(config.memory.persist_dir),
        backup_base_dir=Path("."),
        max_backups=config.memory.max_backups,
        backup_interval_hours=config.memory.backup_interval_hours
    )
    
    return manager.create_backup(force=force)


def list_memory_backups() -> List[BackupInfo]:
    """List all memory backups."""
    from .config import get_config
    
    config = get_config()
    
    manager = BackupManager(
        source_dir=Path(config.memory.persist_dir),
        backup_base_dir=Path("."),
        max_backups=config.memory.max_backups
    )
    
    return manager.list_backups()


def restore_memory_backup(backup_name: Optional[str] = None) -> bool:
    """
    Restore memory from backup.
    
    Args:
        backup_name: Name of backup to restore, or None for latest
    
    Returns:
        True if restore was successful
    """
    from .config import get_config
    
    config = get_config()
    
    manager = BackupManager(
        source_dir=Path(config.memory.persist_dir),
        backup_base_dir=Path("."),
        max_backups=config.memory.max_backups
    )
    
    if backup_name:
        # Find specific backup
        backups = manager.list_backups()
        backup_info = next((b for b in backups if b.path.name == backup_name), None)
        if not backup_info:
            logger.error(f"Backup not found: {backup_name}")
            return False
    else:
        backup_info = None  # Use latest
    
    return manager.restore_backup(backup_info)

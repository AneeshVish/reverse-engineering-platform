import git
import json
import threading
import time
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication, QWidget
from PyQt6.QtWidgets import QVBoxLayout
from PyQt6.QtWidgets import QListWidget
from PyQt6.QtWidgets import QLabel


@dataclass
class REArtifact:
    """Reverse Engineering Artifact"""
    id: str
    type: str  # function, variable, comment, struct
    address: int
    name: str
    data: dict
    author: str
    timestamp: float
    version: int = 1

class CollaborationManager(QObject):
    """Git-based collaboration manager inspired by BinSync"""
    
    artifact_updated = pyqtSignal(dict)  # Emits when remote artifact is updated
    user_joined = pyqtSignal(str)        # Emits when user joins session
    conflict_detected = pyqtSignal(dict) # Emits when merge conflict occurs
    
    def __init__(self, project_path: str, username: str):
        super().__init__()
        self.project_path = Path(project_path)
        self.username = username
        self.repo = None
        self.artifacts: Dict[str, REArtifact] = {}
        self.sync_thread = None
        self.is_syncing = False
        
        self._initialize_repo()
        self._start_sync_thread()
    
    def _initialize_repo(self):
        """Initialize or clone Git repository for collaboration"""
        try:
            if (self.project_path / '.git').exists():
                self.repo = git.Repo(self.project_path)
            else:
                self.repo = git.Repo.init(self.project_path)
                
            # Create user branch if it doesn't exist
            try:
                self.repo.git.checkout(f"user/{self.username}")
            except git.exc.GitCommandError:
                self.repo.git.checkout('-b', f"user/{self.username}")
                
        except Exception as e:
            print(f"Git initialization failed: {e}")
    
    def add_artifact(self, artifact: REArtifact):
        """Add or update a reverse engineering artifact"""
        artifact.author = self.username
        artifact.timestamp = time.time()
        
        # Check for existing artifact and increment version
        if artifact.id in self.artifacts:
            artifact.version = self.artifacts[artifact.id].version + 1
        
        self.artifacts[artifact.id] = artifact
        self._save_artifact(artifact)
        self._commit_changes(f"Update {artifact.type}: {artifact.name}")
    
    def _save_artifact(self, artifact: REArtifact):
        """Save artifact to JSON file"""
        artifact_dir = self.project_path / "artifacts" / artifact.type
        artifact_dir.mkdir(parents=True, exist_ok=True)
        
        artifact_file = artifact_dir / f"{artifact.id}.json"
        with open(artifact_file, 'w') as f:
            json.dump(asdict(artifact), f, indent=2)
    
    def _commit_changes(self, message: str):
        """Commit changes to user branch"""
        try:
            self.repo.git.add(A=True)
            self.repo.index.commit(message)
        except Exception as e:
            print(f"Commit failed: {e}")
    
    def sync_with_remote(self, remote_url: str):
        """Sync with remote repository"""
        try:
            # Add remote if it doesn't exist
            if 'origin' not in [remote.name for remote in self.repo.remotes]:
                self.repo.create_remote('origin', remote_url)
            
            # Push user branch
            origin = self.repo.remotes.origin
            origin.push(f"user/{self.username}")
            
            # Fetch updates from other users
            origin.fetch()
            self._merge_remote_changes()
            
        except Exception as e:
            print(f"Remote sync failed: {e}")
    
    def _merge_remote_changes(self):
        """Merge changes from other user branches"""
        try:
            remote_branches = [ref for ref in self.repo.refs if ref.name.startswith('origin/user/')]
            
            for branch in remote_branches:
                if f"user/{self.username}" not in branch.name:
                    # Get artifacts from other user's branch
                    other_artifacts = self._load_artifacts_from_branch(branch.name)
                    self._merge_artifacts(other_artifacts)
                    
        except Exception as e:
            print(f"Merge failed: {e}")
    
    def _start_sync_thread(self):
        """Start background thread for real-time syncing"""
        def sync_loop():
            while self.is_syncing:
                try:
                    # Pull changes every 5 seconds
                    time.sleep(5)
                    if hasattr(self.repo, 'remotes') and self.repo.remotes:
                        self._merge_remote_changes()
                except Exception as e:
                    print(f"Sync error: {e}")
        
        self.is_syncing = True
        self.sync_thread = threading.Thread(target=sync_loop, daemon=True)
        self.sync_thread.start()
    
    def get_user_artifacts(self, username: str) -> List[REArtifact]:
        """Get all artifacts created by a specific user"""
        return [artifact for artifact in self.artifacts.values() 
                if artifact.author == username]
    
    def resolve_conflicts(self, artifact_id: str, chosen_version: REArtifact):
        """Resolve merge conflicts by choosing a version"""
        self.artifacts[artifact_id] = chosen_version
        self._save_artifact(chosen_version)
        self._commit_changes(f"Resolve conflict for {artifact_id}")

# Real-time collaboration widget for GUI
class CollaborationWidget(QWidget):
    def __init__(self, collaboration_manager: CollaborationManager):
        super().__init__()
        self.collab_manager = collaboration_manager
        self.init_ui()
        self.connect_signals()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Active users list
        self.users_list = QListWidget()
        layout.addWidget(QLabel("Active Users:"))
        layout.addWidget(self.users_list)
        
        # Recent changes
        self.changes_list = QListWidget()
        layout.addWidget(QLabel("Recent Changes:"))
        layout.addWidget(self.changes_list)
        
        # Sync status
        self.sync_status = QLabel("Sync Status: Connected")
        layout.addWidget(self.sync_status)
        
        self.setLayout(layout)
    
    def connect_signals(self):
        self.collab_manager.artifact_updated.connect(self.on_artifact_updated)
        self.collab_manager.user_joined.connect(self.on_user_joined)

import os
import json
from datetime import datetime
import uuid
from typing import List, Dict, Any

class SessionHistoryManager:
    """Manages history saving for individual sessions"""
    
    def __init__(self, base_dir: str = "../Data/sessions"):
        """Initialize the history manager
        
        Args:
            base_dir: Base directory where session files will be stored
        """
        self.base_dir = base_dir
        self.current_session_id = None
        self.current_session_data = []
        self.current_session_name = None
        
    def start_new_session(self, session_name: str = None) -> str:
        """Start a new session and return the session ID
        
        Args:
            session_name: Optional name for the session
        
        Returns:
            str: The new session ID
        """
        # If there's an existing session, save it first
        if self.current_session_id:
            self.save_current_session()
        
        # Generate a new session ID
        self.current_session_id = str(uuid.uuid4())
        self.current_session_data = []
        
        # Store the session name
        self.current_session_name = session_name if session_name else f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Create session metadata
        session_metadata = {
            'session_id': self.current_session_id,
            'session_name': self.current_session_name,
            'start_time': datetime.now().isoformat(),
            'messages': []
        }
        
        # Ensure base directory exists
        os.makedirs(self.base_dir, exist_ok=True)
        
        return self.current_session_id
    
    def add_message(self, message: Dict[str, Any]):
        """Add a message to the current session
        
        Args:
            message: Message data to add
        """
        if not self.current_session_id:
            self.start_new_session()
        
        # Add timestamp if not present
        if 'time' not in message:
            message['time'] = datetime.now().isoformat()
        
        self.current_session_data.append(message)
    
    def save_current_session(self):
        """Save the current session to a file"""
        if not self.current_session_id or not self.current_session_data:
            return
        
        try:
            # Create session filename
            session_filename = f"{self.current_session_id}.json"
            session_path = os.path.join(self.base_dir, session_filename)
            
            # Prepare session data
            session_data = {
                'session_id': self.current_session_id,
                'start_time': datetime.now().isoformat(),
                'end_time': datetime.now().isoformat(),
                'message_count': len(self.current_session_data),
                'messages': self.current_session_data
            }
            
            # Save to file
            with open(session_path, 'w') as f:
                json.dump(session_data, f, indent=2)
            
            # Create index file entry
            self._update_session_index(session_data)
            
        except Exception as e:
            print(f"Error saving session: {e}")
    
    def _update_session_index(self, session_data: Dict[str, Any]):
        """Update the session index file"""
        index_file = os.path.join(self.base_dir, "session_index.json")
        
        try:
            # Load existing index or create new
            if os.path.exists(index_file):
                with open(index_file, 'r') as f:
                    index_data = json.load(f)
            else:
                index_data = {'sessions': []}
            
            # Check if session already exists in index
            session_exists = any(s['session_id'] == session_data['session_id'] for s in index_data['sessions'])
            
            if not session_exists:
                # Add current session to index
                session_entry = {
                    'session_id': session_data['session_id'],
                    'session_name': session_data.get('session_name', self.current_session_name if self.current_session_name else f"session_{session_data['start_time']}"),
                    'start_time': session_data['start_time'],
                    'end_time': session_data['end_time'],
                    'message_count': session_data['message_count'],
                    'filename': f"{session_data['session_id']}.json"
                }
                
                index_data['sessions'].append(session_entry)
            else:
                # Update existing session entry
                for i, session in enumerate(index_data['sessions']):
                    if session['session_id'] == session_data['session_id']:
                        index_data['sessions'][i].update({
                            'session_name': session_data.get('session_name', self.current_session_name if self.current_session_name else f"session_{session_data['start_time']}"),
                            'end_time': session_data['end_time'],
                            'message_count': session_data['message_count']
                        })
                        break
            
            # Save updated index
            with open(index_file, 'w') as f:
                json.dump(index_data, f, indent=2)
                
        except Exception as e:
            print(f"Error updating session index: {e}")
    
    def load_session(self, session_id: str) -> List[Dict[str, Any]]:
        """Load messages from a specific session
        
        Args:
            session_id: ID of the session to load
        
        Returns:
            List of message dictionaries
        """
        session_file = os.path.join(self.base_dir, f"{session_id}.json")
        
        if not os.path.exists(session_file):
            return []
        
        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)
                return session_data.get('messages', [])
        except Exception as e:
            print(f"Error loading session {session_id}: {e}")
            return []
    
    def get_session_list(self) -> List[Dict[str, Any]]:
        """Get a list of all available sessions
        
        Returns:
            List of session information dictionaries
        """
        index_file = os.path.join(self.base_dir, "session_index.json")
        
        if not os.path.exists(index_file):
            return []
        
        try:
            with open(index_file, 'r') as f:
                content = f.read().strip()
                if not content:  # Handle empty file
                    return []
                index_data = json.loads(content)
                return index_data.get('sessions', [])
        except json.JSONDecodeError as e:
            print(f"Error reading session index: {e}")
            # If JSON is corrupted, try to recover by creating a new empty index
            try:
                with open(index_file, 'w') as f:
                    json.dump({'sessions': []}, f)
            except Exception as recovery_error:
                print(f"Failed to recover session index: {recovery_error}")
            return []
        except Exception as e:
            print(f"Error reading session index: {e}")
            return []
    
    def end_current_session(self):
        """End the current session and save it"""
        self.save_current_session()
        self.current_session_id = None
        self.current_session_data = []
    
    def cleanup_old_sessions(self, max_sessions: int = 10):
        """Clean up old sessions, keeping only the most recent
        
        Args:
            max_sessions: Maximum number of sessions to keep
        """
        sessions = self.get_session_list()
        
        if len(sessions) <= max_sessions:
            return
        
        try:
            # Sort by start time (oldest first)
            sessions.sort(key=lambda x: x['start_time'])
            
            # Delete oldest sessions
            for session in sessions[:-max_sessions]:
                session_file = os.path.join(self.base_dir, session['filename'])
                if os.path.exists(session_file):
                    os.remove(session_file)
            
            # Update index
            remaining_sessions = sessions[-max_sessions:]
            index_data = {'sessions': remaining_sessions}
            index_file = os.path.join(self.base_dir, "session_index.json")
            
            with open(index_file, 'w') as f:
                json.dump(index_data, f, indent=2)
                
        except Exception as e:
            print(f"Error cleaning up old sessions: {e}")

class LegacyHistoryManager:
    """Manages legacy history files for backward compatibility"""
    
    def __init__(self):
        self.legacy_files = [
            "../Data/chat_history.json",
            "../Data/server_history.json"
        ]
    
    def migrate_legacy_history(self, session_manager: SessionHistoryManager):
        """Migrate legacy history files to session-based format"""
        for legacy_file in self.legacy_files:
            if os.path.exists(legacy_file):
                try:
                    with open(legacy_file, 'r') as f:
                        legacy_data = json.load(f)
                    
                    if legacy_data:
                        # Create a new session for legacy data
                        session_id = session_manager.start_new_session(
                            session_name=f"legacy_{os.path.basename(legacy_file)}"
                        )
                        
                        # Add all messages to the new session
                        for msg in legacy_data:
                            session_manager.add_message(msg)
                        
                        # Save the session
                        session_manager.save_current_session()
                        
                        # Backup the legacy file
                        backup_file = f"{legacy_file}.backup"
                        os.rename(legacy_file, backup_file)
                        
                except Exception as e:
                    print(f"Error migrating {legacy_file}: {e}")
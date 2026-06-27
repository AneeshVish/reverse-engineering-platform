# -*- coding: utf-8 -*-

import logging
import frida
import subprocess
import threading
from enum import Enum

class DebuggerState(Enum):
    IDLE = 1
    ATTACHED = 2
    RUNNING = 3
    PAUSED = 4
    ERROR = 5

class DebugEngine:
    '''Debug engine using Frida for dynamic instrumentation'''
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.session = None
        self.script = None
        self.state = DebuggerState.IDLE
        self.target_process = None
        self.callbacks = {}
    
    def attach(self, process_name=None, process_id=None):
        '''Attach to a process
        
        Args:
            process_name (str, optional): Name of the process
            process_id (int, optional): Process ID
            
        Returns:
            bool: True if attachment was successful
        '''
        try:
            if process_name:
                self.session = frida.attach(process_name)
                self.target_process = process_name
            elif process_id:
                self.session = frida.attach(process_id)
                self.target_process = process_id
            else:
                self.logger.error("Either process_name or process_id must be provided")
                return False
            
            self.state = DebuggerState.ATTACHED
            self.logger.info(f"Attached to process: {self.target_process}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error attaching to process: {e}")
            self.state = DebuggerState.ERROR
            return False
    
    def spawn(self, program_path, args=None):
        '''Spawn a new process and attach to it
        
        Args:
            program_path (str): Path to the program to spawn
            args (list, optional): Command line arguments
            
        Returns:
            bool: True if spawn was successful
        '''
        try:
            if args is None:
                args = []
            
            pid = frida.spawn([program_path] + args)
            self.session = frida.attach(pid)
            frida.resume(pid)
            
            self.target_process = program_path
            self.state = DebuggerState.ATTACHED
            self.logger.info(f"Spawned and attached to: {program_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error spawning process: {e}")
            self.state = DebuggerState.ERROR
            return False
    
    def inject_script(self, script_source):
        '''Inject a JavaScript script into the target process
        
        Args:
            script_source (str): JavaScript source code
            
        Returns:
            bool: True if injection was successful
        '''
        if self.state != DebuggerState.ATTACHED:
            self.logger.error("Not attached to any process")
            return False
        
        try:
            self.script = self.session.create_script(script_source)
            
            # Set up message handler
            self.script.on('message', self._on_message)
            
            self.script.load()
            self.logger.info("Script injected successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error injecting script: {e}")
            return False
    
    def _on_message(self, message, data):
        '''Handle messages from the injected script'''
        if message['type'] == 'send':
            payload = message['payload']
            if 'log' in payload:
                self.logger.info(f"Script log: {payload['log']}")
            
            # Call registered callbacks
            for callback_name, callback in self.callbacks.items():
                try:
                    callback(message, data)
                except Exception as e:
                    self.logger.error(f"Error in callback {callback_name}: {e}")
        
        elif message['type'] == 'error':
            self.logger.error(f"Script error: {message['description']}")
    
    def register_callback(self, name, callback):
        '''Register a callback for script messages
        
        Args:
            name (str): Name of the callback
            callback (function): Callback function
        '''
        self.callbacks[name] = callback
    
    def unregister_callback(self, name):
        '''Unregister a callback
        
        Args:
            name (str): Name of the callback to remove
        '''
        if name in self.callbacks:
            del self.callbacks[name]
    
    def detach(self):
        '''Detach from the current process'''
        if self.script:
            self.script.unload()
            self.script = None
        
        if self.session:
            self.session.detach()
            self.session = None
        
        self.state = DebuggerState.IDLE
        self.target_process = None
        self.logger.info("Detached from process")
    
    def get_state(self):
        '''Get the current debugger state
        
        Returns:
            DebuggerState: The current state
        '''
        return self.state
    
    def is_attached(self):
        '''Check if debugger is attached to a process
        
        Returns:
            bool: True if attached
        '''
        return self.state == DebuggerState.ATTACHED

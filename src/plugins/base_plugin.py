# -*- coding: utf-8 -*-

class BasePlugin:
   '''Base class for plugins
   
   All plugins should inherit from this class and implement the required methods.
   '''
   
   def __init__(self):
       self.name = self.__class__.__name__
       self.description = "No description provided"
       self.version = "0.1.0"
       self.author = "Unknown"
   
   def get_info(self):
       '''Get plugin information
       
       Returns:
           dict: Plugin information
       '''
       return {
           'name': self.name,
           'description': self.description,
           'version': self.version,
           'author': self.author
       }
   
   # Hook methods that can be implemented by plugins
   
   def on_load(self):
       '''Called when the plugin is loaded'''
       pass
   
   def on_unload(self):
       '''Called when the plugin is unloaded'''
       pass
   
   def on_binary_load(self, binary_info):
       '''Called when a binary is loaded
       
       Args:
           binary_info (dict): Information about the loaded binary
       '''
       pass
   
   def on_disassembly(self, instructions):
       '''Called when disassembly is performed
       
       Args:
           instructions (list): List of disassembled instructions
       '''
       pass
   
   def on_analysis(self, analysis_results):
       '''Called when analysis is performed
       
       Args:
           analysis_results (dict): Analysis results
       '''
       pass

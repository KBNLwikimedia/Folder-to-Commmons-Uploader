# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Workflow

**IMPORTANT**: After every file edit, always create a git commit. This ensures proper version control and traceable changes.

## Project Overview

Folder-to-Commons-Uploader is a platform-agnostic Python tool (supporting both macOS and Windows) that monitors a folder for new files and automatically uploads them to Wikimedia Commons with appropriate metadata.

### Core Functionality

1. **Folder Monitoring**: Watch a specified folder for new files
2. **File Detection**: Detect when new files are added (initially targeting JPEG files)
3. **Metadata Collection**: Gather required metadata from two sources:
   - Static configuration (from `settings.json` or `configuration.json`)
   - User-provided input via Flask web interface
4. **Authentication**: OAuth authentication with Wikimedia Commons
5. **Upload**: Upload files to Wikimedia Commons with complete metadata

### Technology Stack

- **Language**: Python
- **User Interface**: Flask (web-based interface)
- **Authentication**: OAuth for Wikimedia Commons
- **Platform Support**: macOS and Windows (cross-platform)

## Configuration File Structure

The application uses a configuration file (`settings.json` or `configuration.json`) to store default metadata values:

### Default Metadata Settings
- **Own Work**: Whether uploads are user's own work (default setting)
- **Copyright**: Default copyright/license information
- **Categories**: Standard categories to be added to all uploads
- **Other Commons defaults**: Additional metadata that remains consistent across uploads

### User-Provided Metadata
Metadata provided by user through Flask interface:
- File-specific descriptions
- Custom categories
- Other variable metadata

## Wikimedia Commons Integration

### Authentication
- Use OAuth for authentication with Wikimedia Commons
- Store OAuth tokens securely
- Handle token refresh when needed

### Upload Requirements
Uploads to Wikimedia Commons require specific metadata:
- License/copyright information
- Source (e.g., "own work")
- Author/creator
- Description
- Categories

## Development Priorities

1. Implement folder monitoring (cross-platform Python solution)
2. File detection for JPEG files
3. Configuration file reading (`settings.json` / `configuration.json`)
4. OAuth authentication with Wikimedia Commons
5. Flask web interface for user metadata input
6. Wikimedia Commons API integration
7. Upload workflow with combined metadata (config + user input)

## Platform Compatibility Notes

Since this tool must run on both macOS and Windows:
- Use cross-platform Python libraries for file system monitoring
- Ensure configuration file paths work on both platforms
- Test file detection on both operating systems
- Flask web interface provides platform-agnostic UI

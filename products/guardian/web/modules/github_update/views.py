"""
GitHub Update Module Views - API endpoints for GitHub updates

Provides REST API for checking, previewing, and applying updates
from GitHub without CLI access.
"""
from flask import jsonify, request
from . import github_update_bp
from modules.auth import require_auth
from utils import _safe_error
import os
from .git_ops import (
    get_current_status,
    check_for_updates,
    preview_changes,
    pull_updates,
    restart_services,
    get_update_log,
    categorize_changes,
    is_frontend_only_update,
    get_repo_path,
    run_command,
    read_install_config,
    ALLOWED_SERVICES,
    ALLOWED_UPDATE_PATHS,
    REPO_PATH,
    INSTALL_CONFIG_FILE
)


@github_update_bp.route('/status')
def api_status():
    """
    Get current repository status.

    Returns:
        JSON with current commit, branch, and validity status
    """
    try:
        status = get_current_status()
        return jsonify({
            'success': True,
            **status
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': _safe_error(e)
        }), 500


@github_update_bp.route('/check')
def api_check():
    """
    Check for available updates from remote.

    Returns:
        JSON with updates_available, commits_behind, and commit list
    """
    try:
        result = check_for_updates()
        # If result contains an error, return as failure
        if 'error' in result:
            return jsonify({
                'success': False,
                **result
            })
        return jsonify({
            'success': True,
            **result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': _safe_error(e)
        }), 500


@github_update_bp.route('/preview')
def api_preview():
    """
    Preview changes that would be applied.

    Returns:
        JSON with files list (filtered to allowed paths) and services to restart
    """
    try:
        preview = preview_changes()

        # Add categorization for better UI display
        categorization = categorize_changes(preview.get('files', []))

        return jsonify({
            'success': True,
            **preview,
            **categorization,
            'allowed_paths': ALLOWED_UPDATE_PATHS,
            'note': 'Only files in allowed paths will be updated'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': _safe_error(e)
        }), 500


@github_update_bp.route('/pull', methods=['POST'])
@require_auth
def api_pull():
    """
    Pull updates from remote (fast-forward only).

    Request body:
        dry_run: bool - If true, only simulate the pull

    Returns:
        JSON with success status and update details
    """
    try:
        data = request.get_json() or {}
        dry_run = data.get('dry_run', False)

        result = pull_updates(dry_run=dry_run)
        status_code = 200 if result['success'] else 400

        return jsonify(result), status_code
    except Exception as e:
        return jsonify({
            'success': False,
            'error': _safe_error(e)
        }), 500


@github_update_bp.route('/apply', methods=['POST'])
@require_auth
def api_apply():
    """
    Restart services after update.

    Request body:
        services: list - Services to restart (must be in allowed list)

    Returns:
        JSON with restart results for each service
    """
    try:
        data = request.get_json() or {}
        requested_services = data.get('services', [])

        if not requested_services:
            return jsonify({
                'success': False,
                'error': 'No services specified'
            }), 400

        # Validate all services are allowed
        invalid_services = [s for s in requested_services if s not in ALLOWED_SERVICES]
        if invalid_services:
            return jsonify({
                'success': False,
                'error': f'Services not allowed: {invalid_services}',
                'allowed_services': ALLOWED_SERVICES
            }), 403

        result = restart_services(requested_services)
        status_code = 200 if result['success'] else 500

        return jsonify(result), status_code
    except Exception as e:
        return jsonify({
            'success': False,
            'error': _safe_error(e)
        }), 500


@github_update_bp.route('/log')
def api_log():
    """
    Get recent commit log.

    Returns:
        JSON with list of recent commits
    """
    try:
        commits = get_update_log()
        return jsonify({
            'success': True,
            'commits': commits
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': _safe_error(e)
        }), 500


@github_update_bp.route('/config')
def api_config():
    """
    Get update configuration (allowed paths and services).

    Returns:
        JSON with allowed paths and services for transparency
    """
    return jsonify({
        'success': True,
        'allowed_paths': ALLOWED_UPDATE_PATHS,
        'allowed_services': ALLOWED_SERVICES,
        'note': 'Updates are limited to networking components only for safety'
    })


@github_update_bp.route('/debug')
@require_auth
def api_debug():
    """
    Debug endpoint to diagnose git path detection issues.
    Requires authentication. Sensitive paths redacted.
    """
    detected_path = get_repo_path()

    git_test, git_success = run_command(
        ['git', '-C', detected_path, 'rev-parse', '--short', 'HEAD']
    )

    return jsonify({
        'success': True,
        'git_reachable': git_success,
        'git_commit': git_test.strip() if git_test else None,
        'repo_detected': bool(detected_path),
    })

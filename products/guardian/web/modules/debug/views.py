"""
Debug Module Views - API endpoints for browser CLI

Provides REST API and Server-Sent Events (SSE) for real-time
command output streaming in the browser.
"""
from flask import jsonify, request, Response, stream_with_context
from . import debug_bp
from .command_executor import (
    execute_command,
    validate_command,
    generate_help,
    get_command_categories,
    rate_limiter,
    COMMAND_WHITELIST,
    ALLOWED_FILE_PATHS
)
from modules.auth import require_auth


@debug_bp.route('/commands')
@require_auth
def api_commands():
    """
    Get list of available commands grouped by category.

    Returns:
        JSON with command categories and their commands
    """
    categories = get_command_categories()
    return jsonify({
        'success': True,
        'categories': categories,
        'total_commands': len(COMMAND_WHITELIST)
    })


@debug_bp.route('/validate', methods=['POST'])
@require_auth
def api_validate():
    """
    Validate a command without executing it.

    Request body:
        command: str - The command to validate

    Returns:
        JSON with validation result
    """
    data = request.get_json() or {}
    command = data.get('command', '')

    is_valid, error, args = validate_command(command)

    return jsonify({
        'success': True,
        'valid': is_valid,
        'error': error if not is_valid else None,
        'parsed': args if is_valid else None
    })


@debug_bp.route('/execute', methods=['POST'])
@require_auth
def api_execute():
    """
    Execute a command and return output (non-streaming).

    Request body:
        command: str - The command to execute

    Returns:
        JSON with command output
    """
    data = request.get_json() or {}
    command = data.get('command', '')

    if not command:
        return jsonify({
            'success': False,
            'error': 'No command provided'
        }), 400

    # Collect all output
    output_lines = []
    for line in execute_command(command):
        output_lines.append(line)

    output = ''.join(output_lines)

    return jsonify({
        'success': True,
        'command': command,
        'output': output
    })


@debug_bp.route('/stream', methods=['POST'])
@require_auth
def api_stream():
    """
    Execute a command and stream output via Server-Sent Events.

    Request body:
        command: str - The command to execute

    Returns:
        SSE stream with command output
    """
    data = request.get_json() or {}
    command = data.get('command', '')

    if not command:
        def error_stream():
            yield 'data: {"error": "No command provided"}\n\n'
            yield 'event: done\ndata: {}\n\n'

        return Response(
            stream_with_context(error_stream()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no'
            }
        )

    def generate():
        # Send start event
        yield f'event: start\ndata: {{"command": "{command}"}}\n\n'

        # Stream output
        for line in execute_command(command):
            # Escape for JSON
            escaped = line.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
            yield f'data: {{"output": "{escaped}"}}\n\n'

        # Send done event
        yield 'event: done\ndata: {}\n\n'

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )


@debug_bp.route('/help')
def api_help():
    """
    Get help text for all commands.

    Returns:
        JSON with help text
    """
    return jsonify({
        'success': True,
        'help': generate_help()
    })


@debug_bp.route('/help/<command>')
def api_help_command(command):
    """
    Get help for a specific command.

    Returns:
        JSON with command details
    """
    cmd_name = command.lower()

    if cmd_name not in COMMAND_WHITELIST:
        return jsonify({
            'success': False,
            'error': f'Unknown command: {command}'
        }), 404

    spec = COMMAND_WHITELIST[cmd_name]

    return jsonify({
        'success': True,
        'command': {
            'name': spec.name,
            'category': spec.category.value,
            'description': spec.description,
            'timeout': spec.timeout,
            'max_args': spec.max_args,
            'requires_arg': spec.requires_arg,
            'allowed_subcommands': spec.allowed_subcommands,
            'allowed_args': spec.allowed_args
        }
    })


@debug_bp.route('/rate-limit')
def api_rate_limit():
    """
    Get current rate limit status.

    Returns:
        JSON with rate limit info
    """
    return jsonify({
        'success': True,
        'remaining': rate_limiter.get_remaining(),
        'limit': rate_limiter.max_requests,
        'window_seconds': rate_limiter.window_seconds
    })


@debug_bp.route('/allowed-paths')
def api_allowed_paths():
    """
    Get list of allowed file paths for cat/tail/head commands.

    Returns:
        JSON with allowed paths
    """
    return jsonify({
        'success': True,
        'paths': ALLOWED_FILE_PATHS
    })


@debug_bp.route('/history', methods=['POST'])
def api_save_history():
    """
    Save command to history (client-side storage).
    This endpoint just validates and acknowledges.

    Request body:
        command: str - Command to save

    Returns:
        JSON acknowledgement
    """
    data = request.get_json() or {}
    command = data.get('command', '')

    if not command:
        return jsonify({'success': False, 'error': 'No command'}), 400

    # We don't actually store history server-side for privacy
    # Client stores in localStorage
    return jsonify({
        'success': True,
        'message': 'Command recorded (client-side storage)'
    })

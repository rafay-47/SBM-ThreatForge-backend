from utils.powertools_compat import Logger, Tracer
from utils.powertools_compat import Router
from services.threat_designer_service import (
    check_status,
    check_trail,
    delete_tm,
    delete_session,
    fetch_all,
    fetch_owned_paginated,
    fetch_shared_paginated,
    fetch_results,
    generate_presigned_download_url,
    generate_presigned_download_urls_batch,
    generate_presigned_url,
    invoke_lambda,
    restore,
    update_results,
    get_dashboard_stats,
)
from services.collaboration_service import (
    share_threat_model,
    get_collaborators,
    remove_collaborator,
    update_collaborator_access,
    list_users_for_sharing,
)
from services.lock_service import (
    acquire_lock,
    refresh_lock,
    release_lock,
    get_lock_status,
    force_release_lock,
)

tracer = Tracer()
router = Router()

LOG = logger = Logger(serialize_stacktrace=False)


@router.get("/threat-designer/mcp/status/<id>")
@router.get("/threat-designer/status/<id>")
def _tm_status(id):
    path = router.current_event.path
    if "/mcp" in path:
        # MCP endpoints bypass authorization
        return check_status(id)
    else:
        # Extract user_id from request context
        user_id = router.current_event.request_context.authorizer.get("user_id")

        # Verify user has at least READ_ONLY access
        from utils.authorization import require_access

        require_access(id, user_id, required_level="READ_ONLY")

        # Return status if authorized
        return check_status(id)


@router.get("/threat-designer/trail/<id>")
def _tm_trail(id):
    # Extract user_id from request context
    user_id = router.current_event.request_context.authorizer.get("user_id")

    # Verify user has at least READ_ONLY access
    from utils.authorization import require_access

    require_access(id, user_id, required_level="READ_ONLY")

    # Return trail if authorized
    return check_trail(id)


@router.get("/threat-designer/mcp/<id>")
@router.get("/threat-designer/<id>")
def _tm_fetch_results(id):
    path = router.current_event.path
    if "/mcp" in path:
        user_id = "MCP"
    else:
        user_id = router.current_event.request_context.authorizer.get("user_id")

    return fetch_results(id, user_id)


@router.post("/threat-designer/mcp")
@router.post("/threat-designer")
def tm_start():
    try:
        body = router.current_event.json_body

        path = router.current_event.path
        if "/mcp" in path:
            owner = "MCP"
        else:
            owner = router.current_event.request_context.authorizer.get("user_id")

        return invoke_lambda(owner, body)
    except Exception as e:
        LOG.exception(e)


@router.put("/threat-designer/mcp/restore/<id>")
@router.put("/threat-designer/restore/<id>")
def _restore(id):
    path = router.current_event.path
    if "/mcp" in path:
        owner = "MCP"
    else:
        owner = router.current_event.request_context.authorizer.get("user_id")
    return restore(id, owner)


@router.get("/threat-designer/mcp/all")
@router.get("/threat-designer/all")
def _fetch_all():
    try:
        path = router.current_event.path
        if "/mcp" in path:
            owner = "MCP"
        else:
            owner = router.current_event.request_context.authorizer.get("user_id")

        # Extract query parameters
        query_params = router.current_event.query_string_parameters or {}
        filter_mode = query_params.get("filter", "all")
        limit_str = query_params.get("limit")
        cursor = query_params.get("cursor")

        # Validate filter mode
        allowed_filters = ["owned", "shared", "all"]
        if filter_mode not in allowed_filters:
            from utils.powertools_compat import Response
            from utils.powertools_compat import content_types
            import json

            return Response(
                status_code=400,
                content_type=content_types.APPLICATION_JSON,
                body=json.dumps(
                    {"error": "Filter must be 'owned', 'shared', or 'all'"}
                ),
            )

        # Validate limit format (must be integer if provided)
        limit = None
        if limit_str is not None:
            try:
                limit = int(limit_str)
            except ValueError:
                from utils.powertools_compat import Response
                from utils.powertools_compat import content_types
                import json

                return Response(
                    status_code=400,
                    content_type=content_types.APPLICATION_JSON,
                    body=json.dumps(
                        {"error": "Page size must be a valid integer"}
                    ),
                )

        result = fetch_all(owner, limit=limit, cursor=cursor, filter_mode=filter_mode)

        # Handle explicit errors returned from mocked services in tests
        if isinstance(result, dict) and "error" in result:
            from utils.powertools_compat import Response
            from utils.powertools_compat import content_types
            import json

            return Response(
                status_code=400,
                content_type=content_types.APPLICATION_JSON,
                body=json.dumps({"error": result["error"]}),
            )

        return result

    except ValueError as e:
        from utils.powertools_compat import Response
        from utils.powertools_compat import content_types
        import json

        error_msg = str(e)
        if "Page size must be one of" in error_msg:
            error_msg = "Page size must be 10, 20, 50, or 100"

        return Response(
            status_code=400,
            content_type=content_types.APPLICATION_JSON,
            body=json.dumps({"error": error_msg}),
        )
    except Exception as e:
        LOG.exception(e)
        from utils.powertools_compat import Response
        from utils.powertools_compat import content_types
        import json

        return Response(
            status_code=500,
            content_type=content_types.APPLICATION_JSON,
            body=json.dumps({"error": "Failed to fetch threat models"}),
        )


@router.get("/threat-designer/dashboard/stats")
def _dashboard_stats():
    try:
        owner = router.current_event.request_context.authorizer.get("user_id")
        stats_data = get_dashboard_stats(owner)
        
        from utils.powertools_compat import Response, content_types
        import json
        
        return Response(
            status_code=200,
            content_type=content_types.APPLICATION_JSON,
            body=json.dumps({"data": stats_data}),
        )
    except Exception as e:
        LOG.exception(e)
        from utils.powertools_compat import Response, content_types
        import json
        return Response(
            status_code=500,
            content_type=content_types.APPLICATION_JSON,
            body=json.dumps({"error": "Failed to fetch dashboard stats"}),
        )


@router.get("/threat-designer/owned")
def _fetch_owned():
    try:
        owner = router.current_event.request_context.authorizer.get("user_id")
        query_params = router.current_event.query_string_parameters or {}
        limit = int(query_params.get("limit", "10"))
        cursor = query_params.get("cursor")

        return fetch_owned_paginated(owner, limit, cursor)

    except ValueError as e:
        from utils.powertools_compat import Response
        from utils.powertools_compat import content_types
        import json

        return Response(
            status_code=400,
            content_type=content_types.APPLICATION_JSON,
            body=json.dumps({"error": str(e)}),
        )
    except Exception as e:
        LOG.exception(e)
        from utils.powertools_compat import Response
        from utils.powertools_compat import content_types
        import json

        return Response(
            status_code=500,
            content_type=content_types.APPLICATION_JSON,
            body=json.dumps({"error": "Failed to fetch threat models"}),
        )


@router.get("/threat-designer/shared")
def _fetch_shared():
    try:
        user_id = router.current_event.request_context.authorizer.get("user_id")
        query_params = router.current_event.query_string_parameters or {}
        limit = int(query_params.get("limit", "10"))
        cursor = query_params.get("cursor")

        return fetch_shared_paginated(user_id, limit, cursor)

    except ValueError as e:
        from utils.powertools_compat import Response
        from utils.powertools_compat import content_types
        import json

        return Response(
            status_code=400,
            content_type=content_types.APPLICATION_JSON,
            body=json.dumps({"error": str(e)}),
        )
    except Exception as e:
        LOG.exception(e)
        from utils.powertools_compat import Response
        from utils.powertools_compat import content_types
        import json

        return Response(
            status_code=500,
            content_type=content_types.APPLICATION_JSON,
            body=json.dumps({"error": "Failed to fetch threat models"}),
        )


@router.put("/threat-designer/mcp/<id>")
@router.put("/threat-designer/<id>")
def _update_results(id):
    body = router.current_event.json_body
    path = router.current_event.path
    if "/mcp" in path:
        owner = "MCP"
        lock_token = None
    else:
        owner = router.current_event.request_context.authorizer.get("user_id")
        lock_token = body.get("lock_token")

    return update_results(id, body, owner, lock_token)


@router.delete("/threat-designer/mcp/<id>")
@router.delete("/threat-designer/<id>")
def _delete(id):
    path = router.current_event.path
    if "/mcp" in path:
        owner = "MCP"
        force_release = False
    else:
        owner = router.current_event.request_context.authorizer.get("user_id")
        # Check query parameters for force_release flag
        query_params = router.current_event.query_string_parameters or {}
        force_release = query_params.get("force_release", "false").lower() == "true"

    return delete_tm(id, owner, force_release)


@router.delete("/threat-designer/mcp/<id>/session/<session_id>")
@router.delete("/threat-designer/<id>/session/<session_id>")
def _delete_session(id, session_id):
    path = router.current_event.path
    if "/mcp" in path:
        owner = "MCP"
    else:
        owner = router.current_event.request_context.authorizer.get("user_id")
    return delete_session(id, session_id, owner)


@router.post("/threat-designer/mcp/upload")
@router.post("/threat-designer/upload")
def _upload():
    try:
        body = router.current_event.json_body
        file_type = body.get("file_type")

        # Check if direct upload (base64 data provided)
        base64_data = body.get("data")
        if base64_data:
            from services.threat_designer_service import upload_diagram_directly
            return upload_diagram_directly(base64_data, file_type)

        # Otherwise return presigned URL (for S3/AWS mode)
        return generate_presigned_url(file_type)
    except Exception as e:
        LOG.exception(e)


@router.post("/threat-designer/download")
def _download():
    try:
        body = router.current_event.json_body
        threat_model_id = body.get("threat_model_id")

        # Extract user_id from request context
        user_id = router.current_event.request_context.authorizer.get("user_id")

        # Generate presigned URL with authorization check
        return generate_presigned_download_url(threat_model_id, user_id)
    except Exception as e:
        LOG.exception(e)
        raise


@router.post("/threat-designer/download/batch")
def _download_batch():
    """
    Generate presigned URLs for multiple threat models with authorization.

    Request Body:
    {
        "threat_model_ids": ["uuid1", "uuid2", ...]
    }

    Response:
    {
        "results": [
            {
                "threat_model_id": "uuid1",
                "presigned_url": "https://...",
                "success": true
            },
            {
                "threat_model_id": "uuid2",
                "error": "Unauthorized",
                "success": false
            }
        ]
    }
    """
    try:
        from utils.powertools_compat import Response
        from utils.powertools_compat import content_types
        import json

        # Extract user_id from request context
        user_id = router.current_event.request_context.authorizer.get("user_id")

        # Parse and validate request body
        body = router.current_event.json_body

        # Validate threat_model_ids field exists
        if "threat_model_ids" not in body:
            return Response(
                status_code=400,
                content_type=content_types.APPLICATION_JSON,
                body=json.dumps({"error": "Missing required field: threat_model_ids"}),
            )

        threat_model_ids = body.get("threat_model_ids")

        # Validate threat_model_ids is a list
        if not isinstance(threat_model_ids, list):
            return Response(
                status_code=400,
                content_type=content_types.APPLICATION_JSON,
                body=json.dumps({"error": "threat_model_ids must be an array"}),
            )

        # Validate batch size (1-50 items)
        if len(threat_model_ids) == 0:
            return Response(
                status_code=400,
                content_type=content_types.APPLICATION_JSON,
                body=json.dumps({"error": "threat_model_ids array cannot be empty"}),
            )

        if len(threat_model_ids) > 50:
            return Response(
                status_code=400,
                content_type=content_types.APPLICATION_JSON,
                body=json.dumps({"error": "Batch size cannot exceed 50 items"}),
            )

        # Call service layer to generate presigned URLs
        results = generate_presigned_download_urls_batch(threat_model_ids, user_id)

        # Return formatted response
        return {"results": results}

    except Exception as e:
        LOG.exception(e)
        raise


# Collaboration endpoints


@router.post("/threat-designer/<id>/share")
def _share_threat_model(id):
    """Share a threat model with collaborators"""
    try:
        body = router.current_event.json_body
        owner = router.current_event.request_context.authorizer.get("user_id")
        collaborators = body.get("collaborators", [])

        return share_threat_model(id, owner, collaborators)
    except Exception as e:
        LOG.exception(e)
        raise


@router.get("/threat-designer/<id>/collaborators")
def _get_collaborators(id):
    """Get list of collaborators for a threat model"""
    try:
        requester = router.current_event.request_context.authorizer.get("user_id")
        return get_collaborators(id, requester)
    except Exception as e:
        LOG.exception(e)
        raise


@router.delete("/threat-designer/<id>/collaborators/<user_id>")
def _remove_collaborator(id, user_id):
    """Remove a collaborator from a threat model"""
    try:
        owner = router.current_event.request_context.authorizer.get("user_id")
        return remove_collaborator(id, owner, user_id)
    except Exception as e:
        LOG.exception(e)
        raise


@router.put("/threat-designer/<id>/collaborators/<user_id>")
def _update_collaborator_access(id, user_id):
    """Update a collaborator's access level"""
    try:
        body = router.current_event.json_body
        owner = router.current_event.request_context.authorizer.get("user_id")
        new_access_level = body.get("access_level")

        return update_collaborator_access(id, owner, user_id, new_access_level)
    except Exception as e:
        LOG.exception(e)
        raise


@router.get("/threat-designer/users")
def _list_users():
    """List available users for sharing with optional search."""
    try:
        # Get current user
        current_user = router.current_event.request_context.authorizer.get("user_id")

        # Get query parameters
        query_params = router.current_event.query_string_parameters or {}
        search = query_params.get("search")
        limit = int(query_params.get("limit", "100"))

        return list_users_for_sharing(
            search_filter=search, max_results=limit, exclude_user=current_user
        )
    except Exception as e:
        LOG.exception(e)
        raise


# Lock management endpoints


@router.post("/threat-designer/<id>/lock")
def _acquire_lock(id):
    """Acquire an edit lock on a threat model"""
    try:
        user_id = router.current_event.request_context.authorizer.get("user_id")
        result = acquire_lock(id, user_id)

        # Return 409 Conflict if lock is held by another user
        if not result.get("success"):
            from utils.powertools_compat import Response
            from utils.powertools_compat import content_types
            import json

            return Response(
                status_code=409,
                content_type=content_types.APPLICATION_JSON,
                body=json.dumps(result),
            )

        return result
    except Exception as e:
        LOG.exception(e)
        raise


@router.put("/threat-designer/<id>/lock/heartbeat")
def _refresh_lock(id):
    """Refresh lock timestamp (heartbeat)"""
    try:
        body = router.current_event.json_body
        user_id = router.current_event.request_context.authorizer.get("user_id")
        lock_token = body.get("lock_token")

        result = refresh_lock(id, user_id, lock_token)

        # Return 410 Gone if lock is lost
        if not result.get("success") and result.get("status_code") == 410:
            from utils.powertools_compat import Response
            from utils.powertools_compat import content_types
            import json

            return Response(
                status_code=410,
                content_type=content_types.APPLICATION_JSON,
                body=json.dumps(result),
            )

        return result
    except Exception as e:
        LOG.exception(e)
        raise


@router.delete("/threat-designer/<id>/lock")
def _release_lock(id):
    """Release an edit lock gracefully"""
    try:
        body = router.current_event.json_body
        user_id = router.current_event.request_context.authorizer.get("user_id")
        lock_token = body.get("lock_token")

        return release_lock(id, user_id, lock_token)
    except Exception as e:
        LOG.exception(e)
        raise


@router.get("/threat-designer/<id>/lock/status")
def _get_lock_status(id):
    """Get current lock status for a threat model"""
    try:
        return get_lock_status(id)
    except Exception as e:
        LOG.exception(e)
        raise


@router.delete("/threat-designer/<id>/lock/force")
def _force_release_lock(id):
    """Force release a lock (owner only)"""
    try:
        owner = router.current_event.request_context.authorizer.get("user_id")
        return force_release_lock(id, owner)
    except Exception as e:
        LOG.exception(e)
        raise

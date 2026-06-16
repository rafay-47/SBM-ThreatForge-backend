import json
import os
import sys
from pathlib import Path


# Add backend/app to path for imports
backend_path = str(Path(__file__).parent.parent.parent.parent / "backend" / "app")
sys.path.insert(0, backend_path)

os.environ.setdefault("AWS_REGION", "us-east-1")

from utils.powertools_compat import APIGatewayRestResolver, Router


def test_resolve_prefers_static_route_over_parameterized_route():
    app = APIGatewayRestResolver()
    router = Router()

    @router.get("/threat-designer/<id>")
    def _fetch_by_id(id):
        return {"handler": "id", "id": id}

    @router.get("/threat-designer/owned")
    def _fetch_owned():
        return {"handler": "owned"}

    app.include_router(router)

    event = {
        "httpMethod": "GET",
        "path": "/threat-designer/owned",
        "queryStringParameters": {},
        "headers": {},
        "body": None,
        "requestContext": {"http": {"method": "GET"}, "authorizer": {}},
    }

    response = app.resolve(event, None)

    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert body == {"handler": "owned"}

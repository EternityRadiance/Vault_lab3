from __future__ import annotations
from pathlib import Path
from ariadne import load_schema_from_path, make_executable_schema, snake_case_fallback_resolvers
from ariadne.asgi import GraphQL

from app.graphql.context import get_context_value
from app.graphql.directives import IsAdminDirective, IsAuthenticatedDirective
from app.graphql.resolvers import audit_event_type, mutation, query

SCHEMA_PATH = Path(__file__).parent / "schema.graphql"

type_defs = load_schema_from_path(str(SCHEMA_PATH))

schema = make_executable_schema(
    type_defs,
    query,
    mutation,
    audit_event_type,
    snake_case_fallback_resolvers,
    directives={
        "isAuthenticated": IsAuthenticatedDirective,
        "isAdmin": IsAdminDirective,
    },
)

graphql_app = GraphQL(
    schema,
    context_value=get_context_value,
    debug=True,
)
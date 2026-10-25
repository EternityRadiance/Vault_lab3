from __future__ import annotations
from functools import wraps
from ariadne import SchemaDirectiveVisitor
from graphql import default_field_resolver

class IsAuthenticatedDirective(SchemaDirectiveVisitor):
    def visit_field_definition(self, field, object_type):
        original_resolver = field.resolve or default_field_resolver

        @wraps(original_resolver)
        def wrapped_resolver(obj, info, **kwargs):
            user = info.context.get("user")
            if user is None:
                raise PermissionError("Authentication required")
            return original_resolver(obj, info, **kwargs)

        field.resolve = wrapped_resolver
        return field

class IsAdminDirective(SchemaDirectiveVisitor):
    def visit_field_definition(self, field, object_type):
        original_resolver = field.resolve or default_field_resolver

        @wraps(original_resolver)
        def wrapped_resolver(obj, info, **kwargs):
            user = info.context.get("user")
            if user is None:
                raise PermissionError("Authentication required")
            if not user.is_admin:
                raise PermissionError("Admin only")
            return original_resolver(obj, info, **kwargs)

        field.resolve = wrapped_resolver
        return field
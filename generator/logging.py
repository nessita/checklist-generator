import logging


class MissingVariableErrorFilter(logging.Filter):
    """Turn missing template variables DEBUG messages into ERROR logs."""

    ignored_prefixes = (
        "admin/",
        "auth/",
        "django/",
    )

    def filter(self, record):
        if record.msg.startswith("Exception while resolving variable "):
            variable_name, template_name = record.args
            if not template_name.startswith(self.ignored_prefixes):
                record.level = logging.ERROR
                return True
        return False

def analyze_response(response):

    issues = []

    text = response.get("text", "").lower()

    if "sql" in text:
        issues.append("possible_sql_error")

    if "stack trace" in text:
        issues.append("stack_trace_exposed")

    if "exception" in text:
        issues.append("backend_exception")

    return issues
import logging


def test_dump_logger_state():
    mw = logging.getLogger("api.middleware")
    root = logging.getLogger()
    print(
        "\nLOGGER api.middleware: disabled=%r level=%r propagate=%r handlers=%r"
        % (mw.disabled, mw.level, mw.propagate, mw.handlers)
    )
    print(
        "ROOT: disabled=%r level=%r handlers=%r manager.disable=%r"
        % (root.disabled, root.level, root.handlers, logging.root.manager.disable)
    )
    for name in ("api.app", "api.routes", "alembic", "sqlalchemy.engine"):
        lg = logging.getLogger(name)
        print(
            "%s: disabled=%r level=%r propagate=%r"
            % (name, lg.disabled, lg.level, lg.propagate)
        )

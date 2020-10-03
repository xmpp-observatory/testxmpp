import quart.flask_patch

from quart import current_app, request

from flask_sqlalchemy import SQLAlchemy
from flask_babel import Babel

import testxmpp.model


db = SQLAlchemy(metadata=testxmpp.model.Base.metadata)
babel = Babel()


@babel.localeselector
def selected_locale():
    return request.accept_languages.best_match(
        current_app.config['LANGUAGES']
    )

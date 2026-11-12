apps_in_beta = {"some_other_app", "this_one_too"}

# These are bare minimum routers to fake the scenario where there is actually a
# decision around where an application's models might live.


class AlphaRouter:
    # alpha is where the core Django models are stored including user. To keep things
    # simple this is where the oauth2 provider models are stored as well because they
    # have a foreign key to User.

    def db_for_read(self, model, **hints):
        if model._meta.app_label not in apps_in_beta:
            return "alpha"
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label not in apps_in_beta:
            return "alpha"
        return None

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._state.db == "alpha" and obj2._state.db == "alpha":
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label not in apps_in_beta:
            return db == "alpha"
        return None


class BetaRouter:
    def db_for_read(self, model, **hints):
        if model._meta.app_label in apps_in_beta:
            return "beta"
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label in apps_in_beta:
            return "beta"
        return None

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._state.db == "beta" and obj2._state.db == "beta":
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label in apps_in_beta:
            return db == "beta"


class CrossDatabaseRouter:
    # alpha is where the core Django models are stored including user. To keep things
    # simple this is where the oauth2 provider models are stored as well because they
    # have a foreign key to User.
    def db_for_read(self, model, **hints):
        if model._meta.model_name == "accesstoken":
            return "beta"
        return None

    def db_for_write(self, model, **hints):
        if model._meta.model_name == "accesstoken":
            return "beta"
        return None

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._state.db == "beta" and obj2._state.db == "beta":
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if model_name == "accesstoken":
            return db == "beta"
        return None


class SplitTokenRouter:
    """
    Put ``AccessToken`` on ``split_beta`` and every other token on ``split_alpha``.

    This is the configuration the startup check must reject. Unlike
    ``CrossDatabaseRouter`` it permits relations across the two aliases, so a test that
    wants to exercise the write paths past the check is not stopped by Django at
    assignment time. Reads follow writes here; ``SplitTokenReadRouter`` below makes them
    disagree to exercise the read-routing half of the check. The aliases are distinct
    from the ``alpha``/``beta`` aliases in ``tests.multi_db_settings`` so the same test
    runs under both settings modules.
    """

    def db_for_read(self, model, **hints):
        if model._meta.model_name == "accesstoken":
            return "split_beta"
        return "split_alpha"

    def db_for_write(self, model, **hints):
        if model._meta.model_name == "accesstoken":
            return "split_beta"
        return "split_alpha"

    def allow_relation(self, obj1, obj2, **hints):
        if {obj1._state.db, obj2._state.db} <= {"split_alpha", "split_beta"}:
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if model_name == "accesstoken":
            return db == "split_beta"
        return db == "split_alpha"


class SplitTokenReadRouter:
    """Like ``SplitTokenRouter``, but ``db_for_read`` and ``db_for_write`` disagree."""

    def db_for_read(self, model, **hints):
        return "split_alpha"

    def db_for_write(self, model, **hints):
        if model._meta.model_name == "accesstoken":
            return "split_beta"
        return "split_alpha"

    allow_relation = SplitTokenRouter.allow_relation
    allow_migrate = SplitTokenRouter.allow_migrate

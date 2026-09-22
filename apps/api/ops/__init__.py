"""Operator command-line tools -- MBS.SC.

Small, single-purpose commands an operator runs from inside a control-plane container during
an incident. They are deliberately NOT an API: each one requires the same access a person
would need to restart the service, so they introduce no new authentication surface, no new
authorization model, and no new remotely-reachable lever.

Every tool here:
  * calls the EXISTING service function as the single blessed path -- never a bare SQL write,
    which would skip the invariants that function enforces;
  * builds its own short-lived database session (the same pattern the Celery beat tasks and
    the provisioning scripts use), so it depends on no running worker or web process;
  * commits before reporting success, and says plainly if it did not.
"""

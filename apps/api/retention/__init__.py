"""Phase 5.2 -- retention purge foundation (skeleton).

Import-safe without Celery/DB (mirrors the dr/ package): the CLI and unit tests drive
`service.run_purge` directly. Deletes nothing -- eligibility + deletion land in Phase 5.3.
"""

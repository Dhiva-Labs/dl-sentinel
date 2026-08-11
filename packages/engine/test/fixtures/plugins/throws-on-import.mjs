/**
 * Invalid: throws while being imported. Importing a plugin runs its code — this
 * fixture is the reminder that the failure must surface as a usage error with
 * the module's message only, never a stack trace.
 */
throw new Error('fixture plugin exploded during import');

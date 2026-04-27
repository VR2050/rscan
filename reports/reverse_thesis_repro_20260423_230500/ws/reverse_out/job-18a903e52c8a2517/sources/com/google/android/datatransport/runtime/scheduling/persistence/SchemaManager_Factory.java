package com.google.android.datatransport.runtime.scheduling.persistence;

import android.content.Context;
import dagger.internal.Factory;
import javax.inject.Provider;

/* JADX INFO: compiled from: com.google.android.datatransport:transport-runtime@@2.2.0 */
/* JADX INFO: loaded from: classes.dex */
public final class SchemaManager_Factory implements Factory<SchemaManager> {
    private final Provider<Context> contextProvider;
    private final Provider<Integer> schemaVersionProvider;

    public SchemaManager_Factory(Provider<Context> contextProvider, Provider<Integer> schemaVersionProvider) {
        this.contextProvider = contextProvider;
        this.schemaVersionProvider = schemaVersionProvider;
    }

    @Override // javax.inject.Provider
    public SchemaManager get() {
        return new SchemaManager(this.contextProvider.get(), this.schemaVersionProvider.get().intValue());
    }

    public static SchemaManager_Factory create(Provider<Context> contextProvider, Provider<Integer> schemaVersionProvider) {
        return new SchemaManager_Factory(contextProvider, schemaVersionProvider);
    }

    public static SchemaManager newInstance(Context context, int schemaVersion) {
        return new SchemaManager(context, schemaVersion);
    }
}

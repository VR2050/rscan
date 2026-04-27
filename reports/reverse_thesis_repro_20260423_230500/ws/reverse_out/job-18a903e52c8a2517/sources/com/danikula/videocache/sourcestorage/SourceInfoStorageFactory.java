package com.danikula.videocache.sourcestorage;

import android.content.Context;

/* JADX INFO: loaded from: classes.dex */
public class SourceInfoStorageFactory {
    public static SourceInfoStorage newSourceInfoStorage(Context context) {
        return new DatabaseSourceInfoStorage(context);
    }

    public static SourceInfoStorage newEmptySourceInfoStorage() {
        return new NoSourceInfoStorage();
    }
}

package com.danikula.videocache;

import java.io.File;

/* JADX INFO: loaded from: classes.dex */
public interface CacheListener {
    void onCacheAvailable(File file, String str, int i);
}

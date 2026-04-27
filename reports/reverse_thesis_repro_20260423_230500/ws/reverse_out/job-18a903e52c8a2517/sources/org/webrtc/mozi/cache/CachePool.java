package org.webrtc.mozi.cache;

import org.webrtc.mozi.cache.Cache;

/* JADX INFO: loaded from: classes3.dex */
public interface CachePool {
    <T extends Cache.Entry> Cache<T> cache(Class<T> cls);

    <T extends Cache.Entry> boolean cacheable(Class<T> cls);

    void clear();

    void evict(Class<? extends Cache.Entry> cls);
}

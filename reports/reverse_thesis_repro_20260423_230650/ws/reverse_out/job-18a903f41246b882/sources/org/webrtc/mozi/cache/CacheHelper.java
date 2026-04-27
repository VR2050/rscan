package org.webrtc.mozi.cache;

import org.webrtc.mozi.cache.Cache;

/* JADX INFO: loaded from: classes3.dex */
public class CacheHelper {
    public static <T extends Cache.Entry> boolean cacheable(Class<T> tClass) {
        return CachePoolProvider.get().cacheable(tClass);
    }

    public static <T extends Cache.Entry> void offer(Class<T> tClass, String key, T t) {
        Cache<T> cache = CachePoolProvider.get().cache(tClass);
        if (cache != null) {
            cache.offer(key, t);
        }
    }

    public static <T extends Cache.Entry> T poll(Class<T> cls, String str) {
        Cache<T> cache = CachePoolProvider.get().cache(cls);
        if (cache != null) {
            return (T) cache.poll(str);
        }
        return null;
    }

    public static <T extends Cache.Entry> void evict(Class<T> tClass, String key, T t) {
        Cache<T> cache = CachePoolProvider.get().cache(tClass);
        if (cache != null) {
            cache.evict(key, t);
        }
    }

    public static <T extends Cache.Entry> void trim(Class<T> tClass, String key, int maxSize) {
        Cache<T> cache = CachePoolProvider.get().cache(tClass);
        if (cache != null) {
            cache.trim(key, maxSize);
        }
    }

    public static <T extends Cache.Entry> void clear(Class<T> tClass) {
        Cache<T> cache = CachePoolProvider.get().cache(tClass);
        if (cache != null) {
            cache.clear();
        }
    }
}

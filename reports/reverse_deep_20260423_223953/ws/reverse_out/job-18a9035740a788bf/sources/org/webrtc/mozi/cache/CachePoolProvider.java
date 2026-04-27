package org.webrtc.mozi.cache;

import javax.annotation.Nonnull;
import org.webrtc.mozi.Logging;
import org.webrtc.mozi.cache.Cache;

/* JADX INFO: loaded from: classes3.dex */
public class CachePoolProvider {
    private static final String TAG = "CachePoolProvider";
    private volatile CachePool cachePool = EMPTY_POOL;
    private static final CachePool EMPTY_POOL = new CachePool() { // from class: org.webrtc.mozi.cache.CachePoolProvider.1
        @Override // org.webrtc.mozi.cache.CachePool
        public <T extends Cache.Entry> boolean cacheable(Class<T> tClass) {
            return false;
        }

        @Override // org.webrtc.mozi.cache.CachePool
        public <T extends Cache.Entry> Cache<T> cache(Class<T> tClass) {
            return CachePoolProvider.EMPTY_CACHE;
        }

        @Override // org.webrtc.mozi.cache.CachePool
        public void evict(Class<? extends Cache.Entry> tClass) {
        }

        @Override // org.webrtc.mozi.cache.CachePool
        public void clear() {
        }
    };
    private static final Cache<Cache.Entry> EMPTY_CACHE = new Cache<Cache.Entry>() { // from class: org.webrtc.mozi.cache.CachePoolProvider.2
        @Override // org.webrtc.mozi.cache.Cache
        public Cache.Entry poll(String key) {
            return null;
        }

        @Override // org.webrtc.mozi.cache.Cache
        public void evict(String key, Cache.Entry entry) {
        }

        @Override // org.webrtc.mozi.cache.Cache
        public void offer(String key, Cache.Entry entry) {
        }

        @Override // org.webrtc.mozi.cache.Cache
        public void trim(String key, int maxSize) {
        }

        @Override // org.webrtc.mozi.cache.Cache
        public void clear() {
        }
    };

    private static class SingletonInstance {
        private static final CachePoolProvider INSTANCE = new CachePoolProvider();

        private SingletonInstance() {
        }
    }

    public static void setup(CachePool cachePool) {
        if (cachePool != null) {
            SingletonInstance.INSTANCE.cachePool = cachePool;
            Logging.e(TAG, "setup cachePool");
        }
    }

    public static void dispose() {
        SingletonInstance.INSTANCE.cachePool = EMPTY_POOL;
        Logging.e(TAG, "dispose cachePool");
    }

    @Nonnull
    public static CachePool get() {
        return SingletonInstance.INSTANCE.cachePool;
    }
}

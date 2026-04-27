package com.library.cache;

import android.util.LruCache;
import android.util.SparseArray;
import java.lang.ref.SoftReference;

/* JADX INFO: loaded from: classes2.dex */
public class CacheUtil<T> implements CacheInterface<T> {
    private LruCache<Integer, T> mLruCache;
    private SparseArray<SoftReference<T>> mSoftCache;
    private boolean mUseCache = true;

    public CacheUtil() {
        initLruCache();
    }

    public void isCacheable(boolean b) {
        this.mUseCache = b;
    }

    private void initLruCache() {
        this.mLruCache = new LruCache<Integer, T>(2097152) { // from class: com.library.cache.CacheUtil.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // android.util.LruCache
            public void entryRemoved(boolean evicted, Integer key, T oldValue, T newValue) {
                super.entryRemoved(evicted, key, oldValue, newValue);
            }
        };
    }

    @Override // com.library.cache.CacheInterface
    public void put(int position, T t) {
        if (!this.mUseCache) {
            return;
        }
        this.mLruCache.put(Integer.valueOf(position), t);
    }

    @Override // com.library.cache.CacheInterface
    public T get(int position) {
        if (!this.mUseCache) {
            return null;
        }
        return this.mLruCache.get(Integer.valueOf(position));
    }

    @Override // com.library.cache.CacheInterface
    public void remove(int position) {
        if (!this.mUseCache) {
            return;
        }
        this.mLruCache.remove(Integer.valueOf(position));
    }

    @Override // com.library.cache.CacheInterface
    public void clean() {
        this.mLruCache.evictAll();
    }
}

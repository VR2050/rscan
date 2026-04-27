package org.webrtc.mozi.cache;

import org.webrtc.mozi.cache.Cache.Entry;

/* JADX INFO: loaded from: classes3.dex */
public interface Cache<T extends Entry> {

    public interface Entry {
        void cleanup();

        void recycle();

        void reuse();
    }

    void clear();

    void evict(String str, T t);

    void offer(String str, T t);

    T poll(String str);

    void trim(String str, int i);
}

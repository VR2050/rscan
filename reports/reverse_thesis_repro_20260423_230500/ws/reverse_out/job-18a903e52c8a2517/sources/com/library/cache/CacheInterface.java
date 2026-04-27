package com.library.cache;

/* JADX INFO: loaded from: classes2.dex */
public interface CacheInterface<T> {
    void clean();

    T get(int i);

    void put(int i, T t);

    void remove(int i);
}

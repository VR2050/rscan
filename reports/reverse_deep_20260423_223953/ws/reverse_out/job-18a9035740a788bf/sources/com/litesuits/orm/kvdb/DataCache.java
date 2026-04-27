package com.litesuits.orm.kvdb;

import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public interface DataCache<K, V> {
    Object delete(K k);

    List<V> query(String str);

    Object save(K k, V v);

    Object update(K k, V v);
}

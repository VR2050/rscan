package com.alibaba.fastjson.util;

/* JADX INFO: loaded from: classes.dex */
public class IdentityHashMap<K, V> {
    public static final int DEFAULT_TABLE_SIZE = 1024;
    private final Entry<K, V>[] buckets;
    private final int indexMask;

    public IdentityHashMap() {
        this(1024);
    }

    public IdentityHashMap(int tableSize) {
        this.indexMask = tableSize - 1;
        this.buckets = new Entry[tableSize];
    }

    public final V get(K key) {
        int hash = System.identityHashCode(key);
        int bucket = this.indexMask & hash;
        for (Entry<K, V> entry = this.buckets[bucket]; entry != null; entry = entry.next) {
            if (key == entry.key) {
                return entry.value;
            }
        }
        return null;
    }

    public boolean put(K key, V value) {
        int hash = System.identityHashCode(key);
        int bucket = this.indexMask & hash;
        for (Entry<K, V> entry = this.buckets[bucket]; entry != null; entry = entry.next) {
            if (key == entry.key) {
                entry.value = value;
                return true;
            }
        }
        Entry<K, V> entry2 = new Entry<>(key, value, hash, this.buckets[bucket]);
        this.buckets[bucket] = entry2;
        return false;
    }

    public int size() {
        int size = 0;
        int i = 0;
        while (true) {
            Entry<K, V>[] entryArr = this.buckets;
            if (i < entryArr.length) {
                for (Entry<K, V> entry = entryArr[i]; entry != null; entry = entry.next) {
                    size++;
                }
                i++;
            } else {
                return size;
            }
        }
    }

    protected static final class Entry<K, V> {
        public final int hashCode;
        public final K key;
        public final Entry<K, V> next;
        public V value;

        public Entry(K key, V value, int hash, Entry<K, V> next) {
            this.key = key;
            this.value = value;
            this.next = next;
            this.hashCode = hash;
        }
    }
}

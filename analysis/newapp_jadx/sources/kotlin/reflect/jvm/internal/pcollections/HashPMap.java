package kotlin.reflect.jvm.internal.pcollections;

import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class HashPMap<K, V> {
    private static final HashPMap<Object, Object> EMPTY = new HashPMap<>(IntTreePMap.empty(), 0);
    private final IntTreePMap<ConsPStack<MapEntry<K, V>>> intMap;
    private final int size;

    private static /* synthetic */ void $$$reportNull$$$0(int i2) {
        Object[] objArr = new Object[2];
        objArr[0] = "kotlin/reflect/jvm/internal/pcollections/HashPMap";
        if (i2 != 1) {
            objArr[1] = "empty";
        } else {
            objArr[1] = "minus";
        }
        throw new IllegalStateException(String.format("@NotNull method %s.%s must not return null", objArr));
    }

    private HashPMap(IntTreePMap<ConsPStack<MapEntry<K, V>>> intTreePMap, int i2) {
        this.intMap = intTreePMap;
        this.size = i2;
    }

    @NotNull
    public static <K, V> HashPMap<K, V> empty() {
        HashPMap<K, V> hashPMap = (HashPMap<K, V>) EMPTY;
        if (hashPMap == null) {
            $$$reportNull$$$0(0);
        }
        return hashPMap;
    }

    private ConsPStack<MapEntry<K, V>> getEntries(int i2) {
        ConsPStack<MapEntry<K, V>> consPStack = this.intMap.get(i2);
        return consPStack == null ? ConsPStack.empty() : consPStack;
    }

    private static <K, V> int keyIndexIn(ConsPStack<MapEntry<K, V>> consPStack, Object obj) {
        int i2 = 0;
        while (consPStack != null && consPStack.size() > 0) {
            if (consPStack.first.key.equals(obj)) {
                return i2;
            }
            consPStack = consPStack.rest;
            i2++;
        }
        return -1;
    }

    public boolean containsKey(Object obj) {
        return keyIndexIn(getEntries(obj.hashCode()), obj) != -1;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public V get(Object obj) {
        for (ConsPStack entries = getEntries(obj.hashCode()); entries != null && entries.size() > 0; entries = entries.rest) {
            MapEntry mapEntry = (MapEntry) entries.first;
            if (mapEntry.key.equals(obj)) {
                return mapEntry.value;
            }
        }
        return null;
    }

    @NotNull
    public HashPMap<K, V> minus(Object obj) {
        ConsPStack<MapEntry<K, V>> entries = getEntries(obj.hashCode());
        int keyIndexIn = keyIndexIn(entries, obj);
        if (keyIndexIn == -1) {
            return this;
        }
        ConsPStack<MapEntry<K, V>> minus = entries.minus(keyIndexIn);
        return minus.size() == 0 ? new HashPMap<>(this.intMap.minus(obj.hashCode()), this.size - 1) : new HashPMap<>(this.intMap.plus(obj.hashCode(), minus), this.size - 1);
    }

    @NotNull
    public HashPMap<K, V> plus(K k2, V v) {
        ConsPStack<MapEntry<K, V>> entries = getEntries(k2.hashCode());
        int size = entries.size();
        int keyIndexIn = keyIndexIn(entries, k2);
        if (keyIndexIn != -1) {
            entries = entries.minus(keyIndexIn);
        }
        ConsPStack<MapEntry<K, V>> plus = entries.plus(new MapEntry<>(k2, v));
        return new HashPMap<>(this.intMap.plus(k2.hashCode(), plus), plus.size() + (this.size - size));
    }

    public int size() {
        return this.size;
    }
}

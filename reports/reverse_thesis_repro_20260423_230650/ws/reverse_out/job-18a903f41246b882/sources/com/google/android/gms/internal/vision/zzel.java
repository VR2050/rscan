package com.google.android.gms.internal.vision;

import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
final class zzel<E> extends zzbi<E> {
    private static final zzel<Object> zzoa;
    private final List<E> zzmn;

    static {
        zzel<Object> zzelVar = new zzel<>();
        zzoa = zzelVar;
        zzelVar.zzao();
    }

    zzel() {
        this(new ArrayList(10));
    }

    private zzel(List<E> list) {
        this.zzmn = list;
    }

    public static <E> zzel<E> zzdd() {
        return (zzel<E>) zzoa;
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.List
    public final void add(int i, E e) {
        zzap();
        this.zzmn.add(i, e);
        this.modCount++;
    }

    @Override // java.util.AbstractList, java.util.List
    public final E get(int i) {
        return this.zzmn.get(i);
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.List
    public final E remove(int i) {
        zzap();
        E eRemove = this.zzmn.remove(i);
        this.modCount++;
        return eRemove;
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.List
    public final E set(int i, E e) {
        zzap();
        E e2 = this.zzmn.set(i, e);
        this.modCount++;
        return e2;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.zzmn.size();
    }

    @Override // com.google.android.gms.internal.vision.zzcw
    public final /* synthetic */ zzcw zzk(int i) {
        if (i < size()) {
            throw new IllegalArgumentException();
        }
        ArrayList arrayList = new ArrayList(i);
        arrayList.addAll(this.zzmn);
        return new zzel(arrayList);
    }
}

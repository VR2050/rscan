package com.google.android.gms.internal.vision;

import java.util.AbstractList;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.RandomAccess;

/* JADX INFO: loaded from: classes.dex */
public final class zzfi extends AbstractList<String> implements zzdg, RandomAccess {
    private final zzdg zzov;

    public zzfi(zzdg zzdgVar) {
        this.zzov = zzdgVar;
    }

    @Override // java.util.AbstractList, java.util.List
    public final /* synthetic */ Object get(int i) {
        return (String) this.zzov.get(i);
    }

    @Override // com.google.android.gms.internal.vision.zzdg
    public final Object getRaw(int i) {
        return this.zzov.getRaw(i);
    }

    @Override // java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.List
    public final Iterator<String> iterator() {
        return new zzfk(this);
    }

    @Override // java.util.AbstractList, java.util.List
    public final ListIterator<String> listIterator(int i) {
        return new zzfj(this, i);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.zzov.size();
    }

    @Override // com.google.android.gms.internal.vision.zzdg
    public final void zzc(zzbo zzboVar) {
        throw new UnsupportedOperationException();
    }

    @Override // com.google.android.gms.internal.vision.zzdg
    public final List<?> zzck() {
        return this.zzov.zzck();
    }

    @Override // com.google.android.gms.internal.vision.zzdg
    public final zzdg zzcl() {
        return this;
    }
}

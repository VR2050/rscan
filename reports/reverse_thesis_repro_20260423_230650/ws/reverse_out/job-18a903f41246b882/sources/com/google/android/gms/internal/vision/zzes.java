package com.google.android.gms.internal.vision;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* JADX INFO: Add missing generic type declarations: [V, K] */
/* JADX INFO: loaded from: classes.dex */
final class zzes<K, V> implements Iterator<Map.Entry<K, V>> {
    private int pos;
    private Iterator<Map.Entry<K, V>> zzol;
    private final /* synthetic */ zzeq zzom;

    private zzes(zzeq zzeqVar) {
        this.zzom = zzeqVar;
        this.pos = this.zzom.zzog.size();
    }

    /* synthetic */ zzes(zzeq zzeqVar, zzer zzerVar) {
        this(zzeqVar);
    }

    private final Iterator<Map.Entry<K, V>> zzdq() {
        if (this.zzol == null) {
            this.zzol = this.zzom.zzoj.entrySet().iterator();
        }
        return this.zzol;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        int i = this.pos;
        return (i > 0 && i <= this.zzom.zzog.size()) || zzdq().hasNext();
    }

    @Override // java.util.Iterator
    public final /* synthetic */ Object next() {
        Map.Entry<K, V> next;
        if (zzdq().hasNext()) {
            next = zzdq().next();
        } else {
            List list = this.zzom.zzog;
            int i = this.pos - 1;
            this.pos = i;
            next = (Map.Entry<K, V>) list.get(i);
        }
        return next;
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException();
    }
}

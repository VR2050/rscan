package com.google.android.gms.internal.vision;

import java.util.Iterator;
import java.util.Map;

/* JADX INFO: Add missing generic type declarations: [V, K] */
/* JADX INFO: loaded from: classes.dex */
final class zzey<K, V> implements Iterator<Map.Entry<K, V>> {
    private int pos;
    private Iterator<Map.Entry<K, V>> zzol;
    private final /* synthetic */ zzeq zzom;
    private boolean zzoq;

    private zzey(zzeq zzeqVar) {
        this.zzom = zzeqVar;
        this.pos = -1;
    }

    /* synthetic */ zzey(zzeq zzeqVar, zzer zzerVar) {
        this(zzeqVar);
    }

    private final Iterator<Map.Entry<K, V>> zzdq() {
        if (this.zzol == null) {
            this.zzol = this.zzom.zzoh.entrySet().iterator();
        }
        return this.zzol;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.pos + 1 < this.zzom.zzog.size() || (!this.zzom.zzoh.isEmpty() && zzdq().hasNext());
    }

    @Override // java.util.Iterator
    public final /* synthetic */ Object next() {
        this.zzoq = true;
        int i = this.pos + 1;
        this.pos = i;
        return i < this.zzom.zzog.size() ? (Map.Entry<K, V>) this.zzom.zzog.get(this.pos) : zzdq().next();
    }

    @Override // java.util.Iterator
    public final void remove() {
        if (!this.zzoq) {
            throw new IllegalStateException("remove() was called before next()");
        }
        this.zzoq = false;
        this.zzom.zzdo();
        if (this.pos >= this.zzom.zzog.size()) {
            zzdq().remove();
            return;
        }
        zzeq zzeqVar = this.zzom;
        int i = this.pos;
        this.pos = i - 1;
        zzeqVar.zzao(i);
    }
}

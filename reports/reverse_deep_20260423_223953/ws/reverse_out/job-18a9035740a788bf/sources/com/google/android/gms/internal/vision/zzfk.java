package com.google.android.gms.internal.vision;

import java.util.Iterator;

/* JADX INFO: loaded from: classes.dex */
final class zzfk implements Iterator<String> {
    private final /* synthetic */ zzfi zzoy;
    private Iterator<String> zzoz;

    zzfk(zzfi zzfiVar) {
        this.zzoy = zzfiVar;
        this.zzoz = this.zzoy.zzov.iterator();
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.zzoz.hasNext();
    }

    @Override // java.util.Iterator
    public final /* synthetic */ String next() {
        return this.zzoz.next();
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException();
    }
}

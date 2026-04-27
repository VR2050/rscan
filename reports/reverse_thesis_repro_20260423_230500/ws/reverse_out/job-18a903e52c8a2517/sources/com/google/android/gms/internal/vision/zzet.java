package com.google.android.gms.internal.vision;

import java.util.Iterator;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
final class zzet extends zzez {
    private final /* synthetic */ zzeq zzom;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    private zzet(zzeq zzeqVar) {
        super(zzeqVar, null);
        this.zzom = zzeqVar;
    }

    /* synthetic */ zzet(zzeq zzeqVar, zzer zzerVar) {
        this(zzeqVar);
    }

    @Override // com.google.android.gms.internal.vision.zzez, java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator<Map.Entry<K, V>> iterator() {
        return new zzes(this.zzom, null);
    }
}

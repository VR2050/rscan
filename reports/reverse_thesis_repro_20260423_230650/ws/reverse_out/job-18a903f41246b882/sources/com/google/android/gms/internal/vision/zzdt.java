package com.google.android.gms.internal.vision;

import java.util.Iterator;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
final class zzdt implements zzds {
    zzdt() {
    }

    @Override // com.google.android.gms.internal.vision.zzds
    public final int zzb(int i, Object obj, Object obj2) {
        zzdr zzdrVar = (zzdr) obj;
        if (zzdrVar.isEmpty()) {
            return 0;
        }
        Iterator it = zzdrVar.entrySet().iterator();
        if (!it.hasNext()) {
            return 0;
        }
        Map.Entry entry = (Map.Entry) it.next();
        entry.getKey();
        entry.getValue();
        throw new NoSuchMethodError();
    }

    @Override // com.google.android.gms.internal.vision.zzds
    public final Object zzb(Object obj, Object obj2) {
        zzdr zzdrVarZzcq = (zzdr) obj;
        zzdr zzdrVar = (zzdr) obj2;
        if (!zzdrVar.isEmpty()) {
            if (!zzdrVarZzcq.isMutable()) {
                zzdrVarZzcq = zzdrVarZzcq.zzcq();
            }
            zzdrVarZzcq.zza(zzdrVar);
        }
        return zzdrVarZzcq;
    }

    @Override // com.google.android.gms.internal.vision.zzds
    public final Map<?, ?> zzh(Object obj) {
        return (zzdr) obj;
    }

    @Override // com.google.android.gms.internal.vision.zzds
    public final Map<?, ?> zzi(Object obj) {
        return (zzdr) obj;
    }

    @Override // com.google.android.gms.internal.vision.zzds
    public final boolean zzj(Object obj) {
        return !((zzdr) obj).isMutable();
    }

    @Override // com.google.android.gms.internal.vision.zzds
    public final Object zzk(Object obj) {
        ((zzdr) obj).zzao();
        return obj;
    }

    @Override // com.google.android.gms.internal.vision.zzds
    public final Object zzl(Object obj) {
        return zzdr.zzcp().zzcq();
    }

    @Override // com.google.android.gms.internal.vision.zzds
    public final zzdq<?, ?> zzm(Object obj) {
        throw new NoSuchMethodError();
    }
}

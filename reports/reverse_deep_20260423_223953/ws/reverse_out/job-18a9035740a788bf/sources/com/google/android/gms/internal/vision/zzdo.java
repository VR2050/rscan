package com.google.android.gms.internal.vision;

/* JADX INFO: loaded from: classes.dex */
final class zzdo implements zzdw {
    private zzdw[] zzmv;

    zzdo(zzdw... zzdwVarArr) {
        this.zzmv = zzdwVarArr;
    }

    @Override // com.google.android.gms.internal.vision.zzdw
    public final boolean zza(Class<?> cls) {
        for (zzdw zzdwVar : this.zzmv) {
            if (zzdwVar.zza(cls)) {
                return true;
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.vision.zzdw
    public final zzdv zzb(Class<?> cls) {
        for (zzdw zzdwVar : this.zzmv) {
            if (zzdwVar.zza(cls)) {
                return zzdwVar.zzb(cls);
            }
        }
        String strValueOf = String.valueOf(cls.getName());
        throw new UnsupportedOperationException(strValueOf.length() != 0 ? "No factory is available for message type: ".concat(strValueOf) : new String("No factory is available for message type: "));
    }
}

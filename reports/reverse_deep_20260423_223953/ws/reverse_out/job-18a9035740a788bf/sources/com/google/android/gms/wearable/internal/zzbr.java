package com.google.android.gms.wearable.internal;

import com.google.android.gms.common.internal.Preconditions;
import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes.dex */
public final class zzbr extends zzej {
    private final Object lock = new Object();

    @Nullable
    private zzav zzcw;

    @Nullable
    private zzbs zzda;

    public final void zza(zzbs zzbsVar) {
        zzav zzavVar;
        synchronized (this.lock) {
            this.zzda = (zzbs) Preconditions.checkNotNull(zzbsVar);
            zzavVar = this.zzcw;
        }
        if (zzavVar != null) {
            zzbsVar.zzb(zzavVar);
        }
    }

    @Override // com.google.android.gms.wearable.internal.zzei
    public final void zza(int i, int i2) {
        zzbs zzbsVar;
        zzav zzavVar;
        synchronized (this.lock) {
            zzbsVar = this.zzda;
            zzavVar = new zzav(i, i2);
            this.zzcw = zzavVar;
        }
        if (zzbsVar != null) {
            zzbsVar.zzb(zzavVar);
        }
    }
}

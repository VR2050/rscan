package com.google.android.gms.wearable.internal;

import android.os.ParcelFileDescriptor;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.BaseImplementation;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.wearable.Channel;

/* JADX INFO: loaded from: classes.dex */
final class zzgs extends zzgm<Channel.GetInputStreamResult> {
    private final zzbr zzeu;

    public zzgs(BaseImplementation.ResultHolder<Channel.GetInputStreamResult> resultHolder, zzbr zzbrVar) {
        super(resultHolder);
        this.zzeu = (zzbr) Preconditions.checkNotNull(zzbrVar);
    }

    @Override // com.google.android.gms.wearable.internal.zza, com.google.android.gms.wearable.internal.zzek
    public final void zza(zzdm zzdmVar) {
        zzbj zzbjVar;
        if (zzdmVar.zzdr == null) {
            zzbjVar = null;
        } else {
            zzbjVar = new zzbj(new ParcelFileDescriptor.AutoCloseInputStream(zzdmVar.zzdr));
            this.zzeu.zza(new zzbk(zzbjVar));
        }
        zza(new zzbg(new Status(zzdmVar.statusCode), zzbjVar));
    }
}

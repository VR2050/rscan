package com.google.android.gms.internal.wearable;

import com.google.android.gms.internal.wearable.zzn;
import java.io.IOException;

/* JADX INFO: loaded from: classes.dex */
public abstract class zzn<M extends zzn<M>> extends zzt {
    protected zzp zzhc;

    @Override // com.google.android.gms.internal.wearable.zzt
    protected int zzg() {
        if (this.zzhc == null) {
            return 0;
        }
        int iZzg = 0;
        for (int i = 0; i < this.zzhc.size(); i++) {
            iZzg += this.zzhc.zzp(i).zzg();
        }
        return iZzg;
    }

    @Override // com.google.android.gms.internal.wearable.zzt
    public void zza(zzl zzlVar) throws IOException {
        if (this.zzhc == null) {
            return;
        }
        for (int i = 0; i < this.zzhc.size(); i++) {
            this.zzhc.zzp(i).zza(zzlVar);
        }
    }

    protected final boolean zza(zzk zzkVar, int i) throws IOException {
        int position = zzkVar.getPosition();
        if (!zzkVar.zzd(i)) {
            return false;
        }
        int i2 = i >>> 3;
        zzv zzvVar = new zzv(i, zzkVar.zzb(position, zzkVar.getPosition() - position));
        zzq zzqVarZzo = null;
        zzp zzpVar = this.zzhc;
        if (zzpVar == null) {
            this.zzhc = new zzp();
        } else {
            zzqVarZzo = zzpVar.zzo(i2);
        }
        if (zzqVarZzo == null) {
            zzqVarZzo = new zzq();
            this.zzhc.zza(i2, zzqVarZzo);
        }
        zzqVarZzo.zza(zzvVar);
        return true;
    }

    @Override // com.google.android.gms.internal.wearable.zzt
    /* JADX INFO: renamed from: zzs */
    public final /* synthetic */ zzt clone() throws CloneNotSupportedException {
        return (zzn) clone();
    }

    @Override // com.google.android.gms.internal.wearable.zzt
    public /* synthetic */ Object clone() throws CloneNotSupportedException {
        zzn zznVar = (zzn) super.clone();
        zzr.zza(this, zznVar);
        return zznVar;
    }
}

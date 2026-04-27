package com.google.android.gms.internal.wearable;

import java.io.IOException;

/* JADX INFO: loaded from: classes.dex */
public final class zzi extends zzn<zzi> {
    private static volatile zzi[] zzgb;
    public int type = 1;
    public zzj zzgc = null;

    public static zzi[] zzi() {
        if (zzgb == null) {
            synchronized (zzr.zzhk) {
                if (zzgb == null) {
                    zzgb = new zzi[0];
                }
            }
        }
        return zzgb;
    }

    public zzi() {
        this.zzhc = null;
        this.zzhl = -1;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof zzi)) {
            return false;
        }
        zzi zziVar = (zzi) obj;
        if (this.type != zziVar.type) {
            return false;
        }
        zzj zzjVar = this.zzgc;
        if (zzjVar == null) {
            if (zziVar.zzgc != null) {
                return false;
            }
        } else if (!zzjVar.equals(zziVar.zzgc)) {
            return false;
        }
        if (this.zzhc == null || this.zzhc.isEmpty()) {
            return zziVar.zzhc == null || zziVar.zzhc.isEmpty();
        }
        return this.zzhc.equals(zziVar.zzhc);
    }

    public final int hashCode() {
        int iHashCode = ((getClass().getName().hashCode() + 527) * 31) + this.type;
        zzj zzjVar = this.zzgc;
        int iHashCode2 = 0;
        int iHashCode3 = ((iHashCode * 31) + (zzjVar == null ? 0 : zzjVar.hashCode())) * 31;
        if (this.zzhc != null && !this.zzhc.isEmpty()) {
            iHashCode2 = this.zzhc.hashCode();
        }
        return iHashCode3 + iHashCode2;
    }

    @Override // com.google.android.gms.internal.wearable.zzn, com.google.android.gms.internal.wearable.zzt
    public final void zza(zzl zzlVar) throws IOException {
        zzlVar.zzd(1, this.type);
        zzj zzjVar = this.zzgc;
        if (zzjVar != null) {
            zzlVar.zza(2, zzjVar);
        }
        super.zza(zzlVar);
    }

    @Override // com.google.android.gms.internal.wearable.zzn, com.google.android.gms.internal.wearable.zzt
    protected final int zzg() {
        int iZzg = super.zzg() + zzl.zze(1, this.type);
        zzj zzjVar = this.zzgc;
        if (zzjVar != null) {
            return iZzg + zzl.zzb(2, zzjVar);
        }
        return iZzg;
    }

    /* JADX INFO: Access modifiers changed from: private */
    @Override // com.google.android.gms.internal.wearable.zzt
    /* JADX INFO: renamed from: zzb, reason: merged with bridge method [inline-methods] */
    public final zzi zza(zzk zzkVar) throws IOException {
        while (true) {
            int iZzj = zzkVar.zzj();
            if (iZzj == 0) {
                return this;
            }
            if (iZzj == 8) {
                int position = zzkVar.getPosition();
                try {
                    int iZzk = zzkVar.zzk();
                    if (iZzk <= 0 || iZzk > 15) {
                        StringBuilder sb = new StringBuilder(36);
                        sb.append(iZzk);
                        sb.append(" is not a valid enum Type");
                        throw new IllegalArgumentException(sb.toString());
                    }
                    this.type = iZzk;
                } catch (IllegalArgumentException e) {
                    zzkVar.zzg(position);
                    zza(zzkVar, iZzj);
                }
            } else if (iZzj != 18) {
                if (!super.zza(zzkVar, iZzj)) {
                    return this;
                }
            } else {
                if (this.zzgc == null) {
                    this.zzgc = new zzj();
                }
                zzkVar.zza(this.zzgc);
            }
        }
    }
}

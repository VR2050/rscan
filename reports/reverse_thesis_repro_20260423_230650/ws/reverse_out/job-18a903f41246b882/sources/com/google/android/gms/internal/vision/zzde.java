package com.google.android.gms.internal.vision;

/* JADX INFO: loaded from: classes.dex */
public class zzde {
    private static final zzcf zzgk = zzcf.zzbg();
    private zzbo zzmi;
    private volatile zzdx zzmj;
    private volatile zzbo zzmk;

    private final zzdx zzh(zzdx zzdxVar) {
        if (this.zzmj == null) {
            synchronized (this) {
                if (this.zzmj == null) {
                    try {
                        this.zzmj = zzdxVar;
                        this.zzmk = zzbo.zzgt;
                    } catch (zzcx e) {
                        this.zzmj = zzdxVar;
                        this.zzmk = zzbo.zzgt;
                    }
                }
            }
        }
        return this.zzmj;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof zzde)) {
            return false;
        }
        zzde zzdeVar = (zzde) obj;
        zzdx zzdxVar = this.zzmj;
        zzdx zzdxVar2 = zzdeVar.zzmj;
        return (zzdxVar == null && zzdxVar2 == null) ? zzak().equals(zzdeVar.zzak()) : (zzdxVar == null || zzdxVar2 == null) ? zzdxVar != null ? zzdxVar.equals(zzdeVar.zzh(zzdxVar.zzbw())) : zzh(zzdxVar2.zzbw()).equals(zzdxVar2) : zzdxVar.equals(zzdxVar2);
    }

    public int hashCode() {
        return 1;
    }

    public final zzbo zzak() {
        if (this.zzmk != null) {
            return this.zzmk;
        }
        synchronized (this) {
            if (this.zzmk != null) {
                return this.zzmk;
            }
            this.zzmk = this.zzmj == null ? zzbo.zzgt : this.zzmj.zzak();
            return this.zzmk;
        }
    }

    public final int zzbl() {
        if (this.zzmk != null) {
            return this.zzmk.size();
        }
        if (this.zzmj != null) {
            return this.zzmj.zzbl();
        }
        return 0;
    }

    public final zzdx zzi(zzdx zzdxVar) {
        zzdx zzdxVar2 = this.zzmj;
        this.zzmi = null;
        this.zzmk = null;
        this.zzmj = zzdxVar;
        return zzdxVar2;
    }
}

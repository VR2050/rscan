package com.google.android.gms.internal.vision;

import com.google.android.gms.internal.vision.zzcr;

/* JADX INFO: loaded from: classes.dex */
final class zzdm implements zzeo {
    private static final zzdw zzmu = new zzdn();
    private final zzdw zzmt;

    public zzdm() {
        this(new zzdo(zzcq.zzbs(), zzco()));
    }

    private zzdm(zzdw zzdwVar) {
        this.zzmt = (zzdw) zzct.zza(zzdwVar, "messageInfoFactory");
    }

    private static boolean zza(zzdv zzdvVar) {
        return zzdvVar.zzcv() == zzcr.zzd.zzlg;
    }

    private static zzdw zzco() {
        try {
            return (zzdw) Class.forName("com.google.protobuf.DescriptorMessageInfoFactory").getDeclaredMethod("getInstance", new Class[0]).invoke(null, new Object[0]);
        } catch (Exception e) {
            return zzmu;
        }
    }

    @Override // com.google.android.gms.internal.vision.zzeo
    public final <T> zzen<T> zzd(Class<T> cls) {
        zzep.zzf((Class<?>) cls);
        zzdv zzdvVarZzb = this.zzmt.zzb(cls);
        if (zzdvVarZzb.zzcw()) {
            return zzcr.class.isAssignableFrom(cls) ? zzed.zza(zzep.zzdi(), zzci.zzbi(), zzdvVarZzb.zzcx()) : zzed.zza(zzep.zzdg(), zzci.zzbj(), zzdvVarZzb.zzcx());
        }
        if (!zzcr.class.isAssignableFrom(cls)) {
            boolean zZza = zza(zzdvVarZzb);
            zzef zzefVarZzcz = zzeh.zzcz();
            zzdh zzdhVarZzcm = zzdh.zzcm();
            return zZza ? zzeb.zza(cls, zzdvVarZzb, zzefVarZzcz, zzdhVarZzcm, zzep.zzdg(), zzci.zzbj(), zzdu.zzcs()) : zzeb.zza(cls, zzdvVarZzb, zzefVarZzcz, zzdhVarZzcm, zzep.zzdh(), (zzcg<?>) null, zzdu.zzcs());
        }
        boolean zZza2 = zza(zzdvVarZzb);
        zzef zzefVarZzda = zzeh.zzda();
        zzdh zzdhVarZzcn = zzdh.zzcn();
        zzff<?, ?> zzffVarZzdi = zzep.zzdi();
        return zZza2 ? zzeb.zza(cls, zzdvVarZzb, zzefVarZzda, zzdhVarZzcn, zzffVarZzdi, zzci.zzbi(), zzdu.zzct()) : zzeb.zza(cls, zzdvVarZzb, zzefVarZzda, zzdhVarZzcn, zzffVarZzdi, (zzcg<?>) null, zzdu.zzct());
    }
}

package com.google.android.gms.internal.vision;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelWriter;

/* JADX INFO: loaded from: classes.dex */
public final class zzag extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzag> CREATOR = new zzah();
    private final float zzco;
    public final String zzdd;
    public final zzr zzdj;
    private final zzr zzdk;
    public final String zzdm;
    private final zzab[] zzds;
    private final boolean zzdt;

    public zzag(zzab[] zzabVarArr, zzr zzrVar, zzr zzrVar2, String str, float f, String str2, boolean z) {
        this.zzds = zzabVarArr;
        this.zzdj = zzrVar;
        this.zzdk = zzrVar2;
        this.zzdm = str;
        this.zzco = f;
        this.zzdd = str2;
        this.zzdt = z;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iBeginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
        SafeParcelWriter.writeTypedArray(parcel, 2, this.zzds, i, false);
        SafeParcelWriter.writeParcelable(parcel, 3, this.zzdj, i, false);
        SafeParcelWriter.writeParcelable(parcel, 4, this.zzdk, i, false);
        SafeParcelWriter.writeString(parcel, 5, this.zzdm, false);
        SafeParcelWriter.writeFloat(parcel, 6, this.zzco);
        SafeParcelWriter.writeString(parcel, 7, this.zzdd, false);
        SafeParcelWriter.writeBoolean(parcel, 8, this.zzdt);
        SafeParcelWriter.finishObjectHeader(parcel, iBeginObjectHeader);
    }
}

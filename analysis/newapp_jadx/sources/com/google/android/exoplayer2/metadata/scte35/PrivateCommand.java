package com.google.android.exoplayer2.metadata.scte35;

import android.os.Parcel;
import android.os.Parcelable;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class PrivateCommand extends SpliceCommand {
    public static final Parcelable.Creator<PrivateCommand> CREATOR = new C3280a();

    /* renamed from: c */
    public final long f9339c;

    /* renamed from: e */
    public final long f9340e;

    /* renamed from: f */
    public final byte[] f9341f;

    /* renamed from: com.google.android.exoplayer2.metadata.scte35.PrivateCommand$a */
    public static class C3280a implements Parcelable.Creator<PrivateCommand> {
        @Override // android.os.Parcelable.Creator
        public PrivateCommand createFromParcel(Parcel parcel) {
            return new PrivateCommand(parcel, null);
        }

        @Override // android.os.Parcelable.Creator
        public PrivateCommand[] newArray(int i2) {
            return new PrivateCommand[i2];
        }
    }

    public PrivateCommand(long j2, byte[] bArr, long j3) {
        this.f9339c = j3;
        this.f9340e = j2;
        this.f9341f = bArr;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeLong(this.f9339c);
        parcel.writeLong(this.f9340e);
        parcel.writeByteArray(this.f9341f);
    }

    public PrivateCommand(Parcel parcel, C3280a c3280a) {
        this.f9339c = parcel.readLong();
        this.f9340e = parcel.readLong();
        byte[] createByteArray = parcel.createByteArray();
        int i2 = C2344d0.f6035a;
        this.f9341f = createByteArray;
    }
}

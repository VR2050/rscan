package com.google.android.exoplayer2.metadata.id3;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import java.util.Arrays;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class BinaryFrame extends Id3Frame {
    public static final Parcelable.Creator<BinaryFrame> CREATOR = new C3270a();

    /* renamed from: e */
    public final byte[] f9305e;

    /* renamed from: com.google.android.exoplayer2.metadata.id3.BinaryFrame$a */
    public static class C3270a implements Parcelable.Creator<BinaryFrame> {
        @Override // android.os.Parcelable.Creator
        public BinaryFrame createFromParcel(Parcel parcel) {
            return new BinaryFrame(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public BinaryFrame[] newArray(int i2) {
            return new BinaryFrame[i2];
        }
    }

    public BinaryFrame(String str, byte[] bArr) {
        super(str);
        this.f9305e = bArr;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || BinaryFrame.class != obj.getClass()) {
            return false;
        }
        BinaryFrame binaryFrame = (BinaryFrame) obj;
        return this.f9324c.equals(binaryFrame.f9324c) && Arrays.equals(this.f9305e, binaryFrame.f9305e);
    }

    public int hashCode() {
        return Arrays.hashCode(this.f9305e) + C1499a.m598T(this.f9324c, 527, 31);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9324c);
        parcel.writeByteArray(this.f9305e);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public BinaryFrame(android.os.Parcel r3) {
        /*
            r2 = this;
            java.lang.String r0 = r3.readString()
            int r1 = p005b.p199l.p200a.p201a.p250p1.C2344d0.f6035a
            r2.<init>(r0)
            byte[] r3 = r3.createByteArray()
            r2.f9305e = r3
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.metadata.id3.BinaryFrame.<init>(android.os.Parcel):void");
    }
}

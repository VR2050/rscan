package com.google.android.exoplayer2.metadata.id3;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import java.util.Arrays;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class PrivFrame extends Id3Frame {
    public static final Parcelable.Creator<PrivFrame> CREATOR = new C3277a();

    /* renamed from: e */
    public final String f9333e;

    /* renamed from: f */
    public final byte[] f9334f;

    /* renamed from: com.google.android.exoplayer2.metadata.id3.PrivFrame$a */
    public static class C3277a implements Parcelable.Creator<PrivFrame> {
        @Override // android.os.Parcelable.Creator
        public PrivFrame createFromParcel(Parcel parcel) {
            return new PrivFrame(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public PrivFrame[] newArray(int i2) {
            return new PrivFrame[i2];
        }
    }

    public PrivFrame(String str, byte[] bArr) {
        super("PRIV");
        this.f9333e = str;
        this.f9334f = bArr;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || PrivFrame.class != obj.getClass()) {
            return false;
        }
        PrivFrame privFrame = (PrivFrame) obj;
        return C2344d0.m2323a(this.f9333e, privFrame.f9333e) && Arrays.equals(this.f9334f, privFrame.f9334f);
    }

    public int hashCode() {
        String str = this.f9333e;
        return Arrays.hashCode(this.f9334f) + ((527 + (str != null ? str.hashCode() : 0)) * 31);
    }

    @Override // com.google.android.exoplayer2.metadata.id3.Id3Frame
    public String toString() {
        return this.f9324c + ": owner=" + this.f9333e;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9333e);
        parcel.writeByteArray(this.f9334f);
    }

    public PrivFrame(Parcel parcel) {
        super("PRIV");
        String readString = parcel.readString();
        int i2 = C2344d0.f6035a;
        this.f9333e = readString;
        this.f9334f = parcel.createByteArray();
    }
}

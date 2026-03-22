package com.google.android.exoplayer2.metadata.id3;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import java.util.Arrays;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class ApicFrame extends Id3Frame {
    public static final Parcelable.Creator<ApicFrame> CREATOR = new C3269a();

    /* renamed from: e */
    public final String f9301e;

    /* renamed from: f */
    @Nullable
    public final String f9302f;

    /* renamed from: g */
    public final int f9303g;

    /* renamed from: h */
    public final byte[] f9304h;

    /* renamed from: com.google.android.exoplayer2.metadata.id3.ApicFrame$a */
    public static class C3269a implements Parcelable.Creator<ApicFrame> {
        @Override // android.os.Parcelable.Creator
        public ApicFrame createFromParcel(Parcel parcel) {
            return new ApicFrame(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public ApicFrame[] newArray(int i2) {
            return new ApicFrame[i2];
        }
    }

    public ApicFrame(String str, @Nullable String str2, int i2, byte[] bArr) {
        super("APIC");
        this.f9301e = str;
        this.f9302f = str2;
        this.f9303g = i2;
        this.f9304h = bArr;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || ApicFrame.class != obj.getClass()) {
            return false;
        }
        ApicFrame apicFrame = (ApicFrame) obj;
        return this.f9303g == apicFrame.f9303g && C2344d0.m2323a(this.f9301e, apicFrame.f9301e) && C2344d0.m2323a(this.f9302f, apicFrame.f9302f) && Arrays.equals(this.f9304h, apicFrame.f9304h);
    }

    public int hashCode() {
        int i2 = (527 + this.f9303g) * 31;
        String str = this.f9301e;
        int hashCode = (i2 + (str != null ? str.hashCode() : 0)) * 31;
        String str2 = this.f9302f;
        return Arrays.hashCode(this.f9304h) + ((hashCode + (str2 != null ? str2.hashCode() : 0)) * 31);
    }

    @Override // com.google.android.exoplayer2.metadata.id3.Id3Frame
    public String toString() {
        return this.f9324c + ": mimeType=" + this.f9301e + ", description=" + this.f9302f;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9301e);
        parcel.writeString(this.f9302f);
        parcel.writeInt(this.f9303g);
        parcel.writeByteArray(this.f9304h);
    }

    public ApicFrame(Parcel parcel) {
        super("APIC");
        String readString = parcel.readString();
        int i2 = C2344d0.f6035a;
        this.f9301e = readString;
        this.f9302f = parcel.readString();
        this.f9303g = parcel.readInt();
        this.f9304h = parcel.createByteArray();
    }
}

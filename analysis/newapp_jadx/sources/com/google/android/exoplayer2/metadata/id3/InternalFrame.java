package com.google.android.exoplayer2.metadata.id3;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class InternalFrame extends Id3Frame {
    public static final Parcelable.Creator<InternalFrame> CREATOR = new C3275a();

    /* renamed from: e */
    public final String f9325e;

    /* renamed from: f */
    public final String f9326f;

    /* renamed from: g */
    public final String f9327g;

    /* renamed from: com.google.android.exoplayer2.metadata.id3.InternalFrame$a */
    public static class C3275a implements Parcelable.Creator<InternalFrame> {
        @Override // android.os.Parcelable.Creator
        public InternalFrame createFromParcel(Parcel parcel) {
            return new InternalFrame(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public InternalFrame[] newArray(int i2) {
            return new InternalFrame[i2];
        }
    }

    public InternalFrame(String str, String str2, String str3) {
        super("----");
        this.f9325e = str;
        this.f9326f = str2;
        this.f9327g = str3;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || InternalFrame.class != obj.getClass()) {
            return false;
        }
        InternalFrame internalFrame = (InternalFrame) obj;
        return C2344d0.m2323a(this.f9326f, internalFrame.f9326f) && C2344d0.m2323a(this.f9325e, internalFrame.f9325e) && C2344d0.m2323a(this.f9327g, internalFrame.f9327g);
    }

    public int hashCode() {
        String str = this.f9325e;
        int hashCode = (527 + (str != null ? str.hashCode() : 0)) * 31;
        String str2 = this.f9326f;
        int hashCode2 = (hashCode + (str2 != null ? str2.hashCode() : 0)) * 31;
        String str3 = this.f9327g;
        return hashCode2 + (str3 != null ? str3.hashCode() : 0);
    }

    @Override // com.google.android.exoplayer2.metadata.id3.Id3Frame
    public String toString() {
        return this.f9324c + ": domain=" + this.f9325e + ", description=" + this.f9326f;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9324c);
        parcel.writeString(this.f9325e);
        parcel.writeString(this.f9327g);
    }

    public InternalFrame(Parcel parcel) {
        super("----");
        String readString = parcel.readString();
        int i2 = C2344d0.f6035a;
        this.f9325e = readString;
        this.f9326f = parcel.readString();
        this.f9327g = parcel.readString();
    }
}

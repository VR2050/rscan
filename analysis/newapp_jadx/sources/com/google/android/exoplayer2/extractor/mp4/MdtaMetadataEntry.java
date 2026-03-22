package com.google.android.exoplayer2.extractor.mp4;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import java.util.Arrays;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p220h1.C2078a;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class MdtaMetadataEntry implements Metadata.Entry {
    public static final Parcelable.Creator<MdtaMetadataEntry> CREATOR = new C3262a();

    /* renamed from: c */
    public final String f9269c;

    /* renamed from: e */
    public final byte[] f9270e;

    /* renamed from: f */
    public final int f9271f;

    /* renamed from: g */
    public final int f9272g;

    /* renamed from: com.google.android.exoplayer2.extractor.mp4.MdtaMetadataEntry$a */
    public static class C3262a implements Parcelable.Creator<MdtaMetadataEntry> {
        @Override // android.os.Parcelable.Creator
        public MdtaMetadataEntry createFromParcel(Parcel parcel) {
            return new MdtaMetadataEntry(parcel, null);
        }

        @Override // android.os.Parcelable.Creator
        public MdtaMetadataEntry[] newArray(int i2) {
            return new MdtaMetadataEntry[i2];
        }
    }

    public MdtaMetadataEntry(String str, byte[] bArr, int i2, int i3) {
        this.f9269c = str;
        this.f9270e = bArr;
        this.f9271f = i2;
        this.f9272g = i3;
    }

    @Override // com.google.android.exoplayer2.metadata.Metadata.Entry
    /* renamed from: d */
    public /* synthetic */ Format mo4051d() {
        return C2078a.m1704b(this);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || MdtaMetadataEntry.class != obj.getClass()) {
            return false;
        }
        MdtaMetadataEntry mdtaMetadataEntry = (MdtaMetadataEntry) obj;
        return this.f9269c.equals(mdtaMetadataEntry.f9269c) && Arrays.equals(this.f9270e, mdtaMetadataEntry.f9270e) && this.f9271f == mdtaMetadataEntry.f9271f && this.f9272g == mdtaMetadataEntry.f9272g;
    }

    public int hashCode() {
        return ((((Arrays.hashCode(this.f9270e) + C1499a.m598T(this.f9269c, 527, 31)) * 31) + this.f9271f) * 31) + this.f9272g;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("mdta: key=");
        m586H.append(this.f9269c);
        return m586H.toString();
    }

    @Override // com.google.android.exoplayer2.metadata.Metadata.Entry
    /* renamed from: u */
    public /* synthetic */ byte[] mo4052u() {
        return C2078a.m1703a(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9269c);
        parcel.writeInt(this.f9270e.length);
        parcel.writeByteArray(this.f9270e);
        parcel.writeInt(this.f9271f);
        parcel.writeInt(this.f9272g);
    }

    public MdtaMetadataEntry(Parcel parcel, C3262a c3262a) {
        String readString = parcel.readString();
        int i2 = C2344d0.f6035a;
        this.f9269c = readString;
        byte[] bArr = new byte[parcel.readInt()];
        this.f9270e = bArr;
        parcel.readByteArray(bArr);
        this.f9271f = parcel.readInt();
        this.f9272g = parcel.readInt();
    }
}

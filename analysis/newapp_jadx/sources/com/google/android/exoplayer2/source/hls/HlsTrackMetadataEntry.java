package com.google.android.exoplayer2.source.hls;

import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p220h1.C2078a;

/* loaded from: classes.dex */
public final class HlsTrackMetadataEntry implements Metadata.Entry {
    public static final Parcelable.Creator<HlsTrackMetadataEntry> CREATOR = new C3305a();

    /* renamed from: c */
    @Nullable
    public final String f9476c;

    /* renamed from: e */
    @Nullable
    public final String f9477e;

    /* renamed from: f */
    public final List<VariantInfo> f9478f;

    /* renamed from: com.google.android.exoplayer2.source.hls.HlsTrackMetadataEntry$a */
    public static class C3305a implements Parcelable.Creator<HlsTrackMetadataEntry> {
        @Override // android.os.Parcelable.Creator
        public HlsTrackMetadataEntry createFromParcel(Parcel parcel) {
            return new HlsTrackMetadataEntry(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public HlsTrackMetadataEntry[] newArray(int i2) {
            return new HlsTrackMetadataEntry[i2];
        }
    }

    public HlsTrackMetadataEntry(@Nullable String str, @Nullable String str2, List<VariantInfo> list) {
        this.f9476c = str;
        this.f9477e = str2;
        this.f9478f = Collections.unmodifiableList(new ArrayList(list));
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
        if (obj == null || HlsTrackMetadataEntry.class != obj.getClass()) {
            return false;
        }
        HlsTrackMetadataEntry hlsTrackMetadataEntry = (HlsTrackMetadataEntry) obj;
        return TextUtils.equals(this.f9476c, hlsTrackMetadataEntry.f9476c) && TextUtils.equals(this.f9477e, hlsTrackMetadataEntry.f9477e) && this.f9478f.equals(hlsTrackMetadataEntry.f9478f);
    }

    public int hashCode() {
        String str = this.f9476c;
        int hashCode = (str != null ? str.hashCode() : 0) * 31;
        String str2 = this.f9477e;
        return this.f9478f.hashCode() + ((hashCode + (str2 != null ? str2.hashCode() : 0)) * 31);
    }

    public String toString() {
        String str;
        StringBuilder m586H = C1499a.m586H("HlsTrackMetadataEntry");
        if (this.f9476c != null) {
            StringBuilder m586H2 = C1499a.m586H(" [");
            m586H2.append(this.f9476c);
            m586H2.append(", ");
            str = C1499a.m582D(m586H2, this.f9477e, "]");
        } else {
            str = "";
        }
        m586H.append(str);
        return m586H.toString();
    }

    @Override // com.google.android.exoplayer2.metadata.Metadata.Entry
    /* renamed from: u */
    public /* synthetic */ byte[] mo4052u() {
        return C2078a.m1703a(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9476c);
        parcel.writeString(this.f9477e);
        int size = this.f9478f.size();
        parcel.writeInt(size);
        for (int i3 = 0; i3 < size; i3++) {
            parcel.writeParcelable(this.f9478f.get(i3), 0);
        }
    }

    public HlsTrackMetadataEntry(Parcel parcel) {
        this.f9476c = parcel.readString();
        this.f9477e = parcel.readString();
        int readInt = parcel.readInt();
        ArrayList arrayList = new ArrayList(readInt);
        for (int i2 = 0; i2 < readInt; i2++) {
            arrayList.add(parcel.readParcelable(VariantInfo.class.getClassLoader()));
        }
        this.f9478f = Collections.unmodifiableList(arrayList);
    }

    public static final class VariantInfo implements Parcelable {
        public static final Parcelable.Creator<VariantInfo> CREATOR = new C3304a();

        /* renamed from: c */
        public final long f9479c;

        /* renamed from: e */
        @Nullable
        public final String f9480e;

        /* renamed from: f */
        @Nullable
        public final String f9481f;

        /* renamed from: g */
        @Nullable
        public final String f9482g;

        /* renamed from: h */
        @Nullable
        public final String f9483h;

        /* renamed from: com.google.android.exoplayer2.source.hls.HlsTrackMetadataEntry$VariantInfo$a */
        public static class C3304a implements Parcelable.Creator<VariantInfo> {
            @Override // android.os.Parcelable.Creator
            public VariantInfo createFromParcel(Parcel parcel) {
                return new VariantInfo(parcel);
            }

            @Override // android.os.Parcelable.Creator
            public VariantInfo[] newArray(int i2) {
                return new VariantInfo[i2];
            }
        }

        public VariantInfo(long j2, @Nullable String str, @Nullable String str2, @Nullable String str3, @Nullable String str4) {
            this.f9479c = j2;
            this.f9480e = str;
            this.f9481f = str2;
            this.f9482g = str3;
            this.f9483h = str4;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        public boolean equals(@Nullable Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || VariantInfo.class != obj.getClass()) {
                return false;
            }
            VariantInfo variantInfo = (VariantInfo) obj;
            return this.f9479c == variantInfo.f9479c && TextUtils.equals(this.f9480e, variantInfo.f9480e) && TextUtils.equals(this.f9481f, variantInfo.f9481f) && TextUtils.equals(this.f9482g, variantInfo.f9482g) && TextUtils.equals(this.f9483h, variantInfo.f9483h);
        }

        public int hashCode() {
            long j2 = this.f9479c;
            int i2 = ((int) (j2 ^ (j2 >>> 32))) * 31;
            String str = this.f9480e;
            int hashCode = (i2 + (str != null ? str.hashCode() : 0)) * 31;
            String str2 = this.f9481f;
            int hashCode2 = (hashCode + (str2 != null ? str2.hashCode() : 0)) * 31;
            String str3 = this.f9482g;
            int hashCode3 = (hashCode2 + (str3 != null ? str3.hashCode() : 0)) * 31;
            String str4 = this.f9483h;
            return hashCode3 + (str4 != null ? str4.hashCode() : 0);
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i2) {
            parcel.writeLong(this.f9479c);
            parcel.writeString(this.f9480e);
            parcel.writeString(this.f9481f);
            parcel.writeString(this.f9482g);
            parcel.writeString(this.f9483h);
        }

        public VariantInfo(Parcel parcel) {
            this.f9479c = parcel.readLong();
            this.f9480e = parcel.readString();
            this.f9481f = parcel.readString();
            this.f9482g = parcel.readString();
            this.f9483h = parcel.readString();
        }
    }
}

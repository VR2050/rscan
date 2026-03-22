package com.google.android.exoplayer2.drm;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Objects;
import java.util.UUID;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2399v;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class DrmInitData implements Comparator<SchemeData>, Parcelable {
    public static final Parcelable.Creator<DrmInitData> CREATOR = new C3261a();

    /* renamed from: c */
    public final SchemeData[] f9260c;

    /* renamed from: e */
    public int f9261e;

    /* renamed from: f */
    @Nullable
    public final String f9262f;

    /* renamed from: g */
    public final int f9263g;

    /* renamed from: com.google.android.exoplayer2.drm.DrmInitData$a */
    public static class C3261a implements Parcelable.Creator<DrmInitData> {
        @Override // android.os.Parcelable.Creator
        public DrmInitData createFromParcel(Parcel parcel) {
            return new DrmInitData(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public DrmInitData[] newArray(int i2) {
            return new DrmInitData[i2];
        }
    }

    public DrmInitData(@Nullable String str, boolean z, SchemeData... schemeDataArr) {
        this.f9262f = str;
        schemeDataArr = z ? (SchemeData[]) schemeDataArr.clone() : schemeDataArr;
        this.f9260c = schemeDataArr;
        this.f9263g = schemeDataArr.length;
        Arrays.sort(schemeDataArr, this);
    }

    /* renamed from: b */
    public DrmInitData m4048b(@Nullable String str) {
        return C2344d0.m2323a(this.f9262f, str) ? this : new DrmInitData(str, false, this.f9260c);
    }

    @Override // java.util.Comparator
    public int compare(SchemeData schemeData, SchemeData schemeData2) {
        SchemeData schemeData3 = schemeData;
        SchemeData schemeData4 = schemeData2;
        UUID uuid = C2399v.f6327a;
        return uuid.equals(schemeData3.f9265e) ? uuid.equals(schemeData4.f9265e) ? 0 : 1 : schemeData3.f9265e.compareTo(schemeData4.f9265e);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // java.util.Comparator
    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || DrmInitData.class != obj.getClass()) {
            return false;
        }
        DrmInitData drmInitData = (DrmInitData) obj;
        return C2344d0.m2323a(this.f9262f, drmInitData.f9262f) && Arrays.equals(this.f9260c, drmInitData.f9260c);
    }

    public int hashCode() {
        if (this.f9261e == 0) {
            String str = this.f9262f;
            this.f9261e = ((str == null ? 0 : str.hashCode()) * 31) + Arrays.hashCode(this.f9260c);
        }
        return this.f9261e;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9262f);
        parcel.writeTypedArray(this.f9260c, 0);
    }

    public static final class SchemeData implements Parcelable {
        public static final Parcelable.Creator<SchemeData> CREATOR = new C3260a();

        /* renamed from: c */
        public int f9264c;

        /* renamed from: e */
        public final UUID f9265e;

        /* renamed from: f */
        @Nullable
        public final String f9266f;

        /* renamed from: g */
        public final String f9267g;

        /* renamed from: h */
        @Nullable
        public final byte[] f9268h;

        /* renamed from: com.google.android.exoplayer2.drm.DrmInitData$SchemeData$a */
        public static class C3260a implements Parcelable.Creator<SchemeData> {
            @Override // android.os.Parcelable.Creator
            public SchemeData createFromParcel(Parcel parcel) {
                return new SchemeData(parcel);
            }

            @Override // android.os.Parcelable.Creator
            public SchemeData[] newArray(int i2) {
                return new SchemeData[i2];
            }
        }

        public SchemeData(UUID uuid, @Nullable String str, String str2, @Nullable byte[] bArr) {
            Objects.requireNonNull(uuid);
            this.f9265e = uuid;
            this.f9266f = str;
            Objects.requireNonNull(str2);
            this.f9267g = str2;
            this.f9268h = bArr;
        }

        /* renamed from: b */
        public boolean m4049b() {
            return this.f9268h != null;
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        /* renamed from: e */
        public boolean m4050e(UUID uuid) {
            return C2399v.f6327a.equals(this.f9265e) || uuid.equals(this.f9265e);
        }

        public boolean equals(@Nullable Object obj) {
            if (!(obj instanceof SchemeData)) {
                return false;
            }
            if (obj == this) {
                return true;
            }
            SchemeData schemeData = (SchemeData) obj;
            return C2344d0.m2323a(this.f9266f, schemeData.f9266f) && C2344d0.m2323a(this.f9267g, schemeData.f9267g) && C2344d0.m2323a(this.f9265e, schemeData.f9265e) && Arrays.equals(this.f9268h, schemeData.f9268h);
        }

        public int hashCode() {
            if (this.f9264c == 0) {
                int hashCode = this.f9265e.hashCode() * 31;
                String str = this.f9266f;
                this.f9264c = Arrays.hashCode(this.f9268h) + C1499a.m598T(this.f9267g, (hashCode + (str == null ? 0 : str.hashCode())) * 31, 31);
            }
            return this.f9264c;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i2) {
            parcel.writeLong(this.f9265e.getMostSignificantBits());
            parcel.writeLong(this.f9265e.getLeastSignificantBits());
            parcel.writeString(this.f9266f);
            parcel.writeString(this.f9267g);
            parcel.writeByteArray(this.f9268h);
        }

        public SchemeData(Parcel parcel) {
            this.f9265e = new UUID(parcel.readLong(), parcel.readLong());
            this.f9266f = parcel.readString();
            String readString = parcel.readString();
            int i2 = C2344d0.f6035a;
            this.f9267g = readString;
            this.f9268h = parcel.createByteArray();
        }
    }

    public DrmInitData(Parcel parcel) {
        this.f9262f = parcel.readString();
        Object[] createTypedArray = parcel.createTypedArray(SchemeData.CREATOR);
        int i2 = C2344d0.f6035a;
        SchemeData[] schemeDataArr = (SchemeData[]) createTypedArray;
        this.f9260c = schemeDataArr;
        this.f9263g = schemeDataArr.length;
    }
}

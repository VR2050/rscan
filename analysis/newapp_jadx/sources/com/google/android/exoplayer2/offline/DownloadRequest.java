package com.google.android.exoplayer2.offline;

import android.net.Uri;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class DownloadRequest implements Parcelable {
    public static final Parcelable.Creator<DownloadRequest> CREATOR = new C3288a();

    /* renamed from: c */
    public final String f9374c;

    /* renamed from: e */
    public final String f9375e;

    /* renamed from: f */
    public final Uri f9376f;

    /* renamed from: g */
    public final List<StreamKey> f9377g;

    /* renamed from: h */
    @Nullable
    public final String f9378h;

    /* renamed from: i */
    public final byte[] f9379i;

    /* renamed from: com.google.android.exoplayer2.offline.DownloadRequest$a */
    public static class C3288a implements Parcelable.Creator<DownloadRequest> {
        @Override // android.os.Parcelable.Creator
        public DownloadRequest createFromParcel(Parcel parcel) {
            return new DownloadRequest(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public DownloadRequest[] newArray(int i2) {
            return new DownloadRequest[i2];
        }
    }

    public DownloadRequest(Parcel parcel) {
        String readString = parcel.readString();
        int i2 = C2344d0.f6035a;
        this.f9374c = readString;
        this.f9375e = parcel.readString();
        this.f9376f = Uri.parse(parcel.readString());
        int readInt = parcel.readInt();
        ArrayList arrayList = new ArrayList(readInt);
        for (int i3 = 0; i3 < readInt; i3++) {
            arrayList.add(parcel.readParcelable(StreamKey.class.getClassLoader()));
        }
        this.f9377g = Collections.unmodifiableList(arrayList);
        this.f9378h = parcel.readString();
        this.f9379i = parcel.createByteArray();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(@Nullable Object obj) {
        if (!(obj instanceof DownloadRequest)) {
            return false;
        }
        DownloadRequest downloadRequest = (DownloadRequest) obj;
        return this.f9374c.equals(downloadRequest.f9374c) && this.f9375e.equals(downloadRequest.f9375e) && this.f9376f.equals(downloadRequest.f9376f) && this.f9377g.equals(downloadRequest.f9377g) && C2344d0.m2323a(this.f9378h, downloadRequest.f9378h) && Arrays.equals(this.f9379i, downloadRequest.f9379i);
    }

    public final int hashCode() {
        int hashCode = (this.f9377g.hashCode() + ((this.f9376f.hashCode() + C1499a.m598T(this.f9375e, C1499a.m598T(this.f9374c, this.f9375e.hashCode() * 31, 31), 31)) * 31)) * 31;
        String str = this.f9378h;
        return Arrays.hashCode(this.f9379i) + ((hashCode + (str != null ? str.hashCode() : 0)) * 31);
    }

    public String toString() {
        return this.f9375e + ":" + this.f9374c;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.f9374c);
        parcel.writeString(this.f9375e);
        parcel.writeString(this.f9376f.toString());
        parcel.writeInt(this.f9377g.size());
        for (int i3 = 0; i3 < this.f9377g.size(); i3++) {
            parcel.writeParcelable(this.f9377g.get(i3), 0);
        }
        parcel.writeString(this.f9378h);
        parcel.writeByteArray(this.f9379i);
    }
}

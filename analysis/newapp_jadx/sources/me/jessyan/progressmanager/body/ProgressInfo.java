package me.jessyan.progressmanager.body;

import android.os.Parcel;
import android.os.Parcelable;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class ProgressInfo implements Parcelable {
    public static final Parcelable.Creator<ProgressInfo> CREATOR = new C4953a();

    /* renamed from: c */
    public long f12632c;

    /* renamed from: e */
    public long f12633e;

    /* renamed from: f */
    public long f12634f;

    /* renamed from: g */
    public long f12635g;

    /* renamed from: h */
    public long f12636h;

    /* renamed from: i */
    public boolean f12637i;

    /* renamed from: me.jessyan.progressmanager.body.ProgressInfo$a */
    public static class C4953a implements Parcelable.Creator<ProgressInfo> {
        @Override // android.os.Parcelable.Creator
        public ProgressInfo createFromParcel(Parcel parcel) {
            return new ProgressInfo(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public ProgressInfo[] newArray(int i2) {
            return new ProgressInfo[i2];
        }
    }

    public ProgressInfo(long j2) {
        this.f12636h = j2;
    }

    /* renamed from: b */
    public int m5618b() {
        long j2 = this.f12632c;
        if (j2 <= 0) {
            return 0;
        }
        long j3 = this.f12633e;
        if (j3 <= 0) {
            return 0;
        }
        return (int) ((j2 * 100) / j3);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("ProgressInfo{id=");
        m586H.append(this.f12636h);
        m586H.append(", currentBytes=");
        m586H.append(this.f12632c);
        m586H.append(", contentLength=");
        m586H.append(this.f12633e);
        m586H.append(", eachBytes=");
        m586H.append(this.f12635g);
        m586H.append(", intervalTime=");
        m586H.append(this.f12634f);
        m586H.append(", finish=");
        m586H.append(this.f12637i);
        m586H.append('}');
        return m586H.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeLong(this.f12632c);
        parcel.writeLong(this.f12633e);
        parcel.writeLong(this.f12634f);
        parcel.writeLong(this.f12635g);
        parcel.writeLong(this.f12636h);
        parcel.writeByte(this.f12637i ? (byte) 1 : (byte) 0);
    }

    public ProgressInfo(Parcel parcel) {
        this.f12632c = parcel.readLong();
        this.f12633e = parcel.readLong();
        this.f12634f = parcel.readLong();
        this.f12635g = parcel.readLong();
        this.f12636h = parcel.readLong();
        this.f12637i = parcel.readByte() != 0;
    }
}

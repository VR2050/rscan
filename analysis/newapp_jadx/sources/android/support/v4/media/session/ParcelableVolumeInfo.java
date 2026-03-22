package android.support.v4.media.session;

import android.os.Parcel;
import android.os.Parcelable;

/* loaded from: classes.dex */
public class ParcelableVolumeInfo implements Parcelable {
    public static final Parcelable.Creator<ParcelableVolumeInfo> CREATOR = new C0029a();

    /* renamed from: c */
    public int f75c;

    /* renamed from: e */
    public int f76e;

    /* renamed from: f */
    public int f77f;

    /* renamed from: g */
    public int f78g;

    /* renamed from: h */
    public int f79h;

    /* renamed from: android.support.v4.media.session.ParcelableVolumeInfo$a */
    public static class C0029a implements Parcelable.Creator<ParcelableVolumeInfo> {
        @Override // android.os.Parcelable.Creator
        public ParcelableVolumeInfo createFromParcel(Parcel parcel) {
            return new ParcelableVolumeInfo(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public ParcelableVolumeInfo[] newArray(int i2) {
            return new ParcelableVolumeInfo[i2];
        }
    }

    public ParcelableVolumeInfo(Parcel parcel) {
        this.f75c = parcel.readInt();
        this.f77f = parcel.readInt();
        this.f78g = parcel.readInt();
        this.f79h = parcel.readInt();
        this.f76e = parcel.readInt();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeInt(this.f75c);
        parcel.writeInt(this.f77f);
        parcel.writeInt(this.f78g);
        parcel.writeInt(this.f79h);
        parcel.writeInt(this.f76e);
    }
}

package androidx.fragment.app;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.fragment.app.x;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes.dex */
final class z implements Parcelable {
    public static final Parcelable.Creator<z> CREATOR = new a();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    ArrayList f5085a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    ArrayList f5086b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    C0290b[] f5087c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    int f5088d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    String f5089e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    ArrayList f5090f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    ArrayList f5091g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    ArrayList f5092h;

    class a implements Parcelable.Creator {
        a() {
        }

        @Override // android.os.Parcelable.Creator
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public z createFromParcel(Parcel parcel) {
            return new z(parcel);
        }

        @Override // android.os.Parcelable.Creator
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public z[] newArray(int i3) {
            return new z[i3];
        }
    }

    public z() {
        this.f5089e = null;
        this.f5090f = new ArrayList();
        this.f5091g = new ArrayList();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i3) {
        parcel.writeStringList(this.f5085a);
        parcel.writeStringList(this.f5086b);
        parcel.writeTypedArray(this.f5087c, i3);
        parcel.writeInt(this.f5088d);
        parcel.writeString(this.f5089e);
        parcel.writeStringList(this.f5090f);
        parcel.writeTypedList(this.f5091g);
        parcel.writeTypedList(this.f5092h);
    }

    public z(Parcel parcel) {
        this.f5089e = null;
        this.f5090f = new ArrayList();
        this.f5091g = new ArrayList();
        this.f5085a = parcel.createStringArrayList();
        this.f5086b = parcel.createStringArrayList();
        this.f5087c = (C0290b[]) parcel.createTypedArray(C0290b.CREATOR);
        this.f5088d = parcel.readInt();
        this.f5089e = parcel.readString();
        this.f5090f = parcel.createStringArrayList();
        this.f5091g = parcel.createTypedArrayList(C0291c.CREATOR);
        this.f5092h = parcel.createTypedArrayList(x.k.CREATOR);
    }
}

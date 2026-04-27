package androidx.fragment.app;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.List;

/* JADX INFO: renamed from: androidx.fragment.app.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0291c implements Parcelable {
    public static final Parcelable.Creator<C0291c> CREATOR = new a();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final List f4915a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final List f4916b;

    /* JADX INFO: renamed from: androidx.fragment.app.c$a */
    class a implements Parcelable.Creator {
        a() {
        }

        @Override // android.os.Parcelable.Creator
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public C0291c createFromParcel(Parcel parcel) {
            return new C0291c(parcel);
        }

        @Override // android.os.Parcelable.Creator
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public C0291c[] newArray(int i3) {
            return new C0291c[i3];
        }
    }

    C0291c(Parcel parcel) {
        this.f4915a = parcel.createStringArrayList();
        this.f4916b = parcel.createTypedArrayList(C0290b.CREATOR);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i3) {
        parcel.writeStringList(this.f4915a);
        parcel.writeTypedList(this.f4916b);
    }
}

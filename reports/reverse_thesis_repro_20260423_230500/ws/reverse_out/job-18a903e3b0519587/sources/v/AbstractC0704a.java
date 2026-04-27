package v;

import android.os.Parcel;
import android.os.Parcelable;

/* JADX INFO: renamed from: v.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0704a implements Parcelable {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Parcelable f10237a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final AbstractC0704a f10236b = new C0150a();
    public static final Parcelable.Creator<AbstractC0704a> CREATOR = new b();

    /* JADX INFO: renamed from: v.a$a, reason: collision with other inner class name */
    static class C0150a extends AbstractC0704a {
        C0150a() {
            super((C0150a) null);
        }
    }

    /* JADX INFO: renamed from: v.a$b */
    static class b implements Parcelable.ClassLoaderCreator {
        b() {
        }

        @Override // android.os.Parcelable.Creator
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public AbstractC0704a createFromParcel(Parcel parcel) {
            return createFromParcel(parcel, null);
        }

        @Override // android.os.Parcelable.ClassLoaderCreator
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public AbstractC0704a createFromParcel(Parcel parcel, ClassLoader classLoader) {
            if (parcel.readParcelable(classLoader) == null) {
                return AbstractC0704a.f10236b;
            }
            throw new IllegalStateException("superState must be null");
        }

        @Override // android.os.Parcelable.Creator
        /* JADX INFO: renamed from: c, reason: merged with bridge method [inline-methods] */
        public AbstractC0704a[] newArray(int i3) {
            return new AbstractC0704a[i3];
        }
    }

    /* synthetic */ AbstractC0704a(C0150a c0150a) {
        this();
    }

    public final Parcelable a() {
        return this.f10237a;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i3) {
        parcel.writeParcelable(this.f10237a, i3);
    }

    private AbstractC0704a() {
        this.f10237a = null;
    }

    protected AbstractC0704a(Parcelable parcelable) {
        if (parcelable != null) {
            this.f10237a = parcelable == f10236b ? null : parcelable;
            return;
        }
        throw new IllegalArgumentException("superState must not be null");
    }

    protected AbstractC0704a(Parcel parcel, ClassLoader classLoader) {
        Parcelable parcelable = parcel.readParcelable(classLoader);
        this.f10237a = parcelable == null ? f10236b : parcelable;
    }
}

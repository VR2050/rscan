package androidx.fragment.app;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.lifecycle.f;

/* JADX INFO: loaded from: classes.dex */
final class C implements Parcelable {
    public static final Parcelable.Creator<C> CREATOR = new a();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final String f4701a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final String f4702b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    final boolean f4703c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    final int f4704d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    final int f4705e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    final String f4706f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    final boolean f4707g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    final boolean f4708h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    final boolean f4709i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    final Bundle f4710j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    final boolean f4711k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    final int f4712l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    Bundle f4713m;

    class a implements Parcelable.Creator {
        a() {
        }

        @Override // android.os.Parcelable.Creator
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public C createFromParcel(Parcel parcel) {
            return new C(parcel);
        }

        @Override // android.os.Parcelable.Creator
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public C[] newArray(int i3) {
            return new C[i3];
        }
    }

    C(Fragment fragment) {
        this.f4701a = fragment.getClass().getName();
        this.f4702b = fragment.f4788g;
        this.f4703c = fragment.f4797p;
        this.f4704d = fragment.f4806y;
        this.f4705e = fragment.f4807z;
        this.f4706f = fragment.f4755A;
        this.f4707g = fragment.f4758D;
        this.f4708h = fragment.f4795n;
        this.f4709i = fragment.f4757C;
        this.f4710j = fragment.f4789h;
        this.f4711k = fragment.f4756B;
        this.f4712l = fragment.f4773S.ordinal();
    }

    Fragment a(o oVar, ClassLoader classLoader) {
        Fragment fragmentA = oVar.a(classLoader, this.f4701a);
        Bundle bundle = this.f4710j;
        if (bundle != null) {
            bundle.setClassLoader(classLoader);
        }
        fragmentA.r1(this.f4710j);
        fragmentA.f4788g = this.f4702b;
        fragmentA.f4797p = this.f4703c;
        fragmentA.f4799r = true;
        fragmentA.f4806y = this.f4704d;
        fragmentA.f4807z = this.f4705e;
        fragmentA.f4755A = this.f4706f;
        fragmentA.f4758D = this.f4707g;
        fragmentA.f4795n = this.f4708h;
        fragmentA.f4757C = this.f4709i;
        fragmentA.f4756B = this.f4711k;
        fragmentA.f4773S = f.b.values()[this.f4712l];
        Bundle bundle2 = this.f4713m;
        if (bundle2 != null) {
            fragmentA.f4784c = bundle2;
        } else {
            fragmentA.f4784c = new Bundle();
        }
        return fragmentA;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder(128);
        sb.append("FragmentState{");
        sb.append(this.f4701a);
        sb.append(" (");
        sb.append(this.f4702b);
        sb.append(")}:");
        if (this.f4703c) {
            sb.append(" fromLayout");
        }
        if (this.f4705e != 0) {
            sb.append(" id=0x");
            sb.append(Integer.toHexString(this.f4705e));
        }
        String str = this.f4706f;
        if (str != null && !str.isEmpty()) {
            sb.append(" tag=");
            sb.append(this.f4706f);
        }
        if (this.f4707g) {
            sb.append(" retainInstance");
        }
        if (this.f4708h) {
            sb.append(" removing");
        }
        if (this.f4709i) {
            sb.append(" detached");
        }
        if (this.f4711k) {
            sb.append(" hidden");
        }
        return sb.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i3) {
        parcel.writeString(this.f4701a);
        parcel.writeString(this.f4702b);
        parcel.writeInt(this.f4703c ? 1 : 0);
        parcel.writeInt(this.f4704d);
        parcel.writeInt(this.f4705e);
        parcel.writeString(this.f4706f);
        parcel.writeInt(this.f4707g ? 1 : 0);
        parcel.writeInt(this.f4708h ? 1 : 0);
        parcel.writeInt(this.f4709i ? 1 : 0);
        parcel.writeBundle(this.f4710j);
        parcel.writeInt(this.f4711k ? 1 : 0);
        parcel.writeBundle(this.f4713m);
        parcel.writeInt(this.f4712l);
    }

    C(Parcel parcel) {
        this.f4701a = parcel.readString();
        this.f4702b = parcel.readString();
        this.f4703c = parcel.readInt() != 0;
        this.f4704d = parcel.readInt();
        this.f4705e = parcel.readInt();
        this.f4706f = parcel.readString();
        this.f4707g = parcel.readInt() != 0;
        this.f4708h = parcel.readInt() != 0;
        this.f4709i = parcel.readInt() != 0;
        this.f4710j = parcel.readBundle();
        this.f4711k = parcel.readInt() != 0;
        this.f4713m = parcel.readBundle();
        this.f4712l = parcel.readInt();
    }
}

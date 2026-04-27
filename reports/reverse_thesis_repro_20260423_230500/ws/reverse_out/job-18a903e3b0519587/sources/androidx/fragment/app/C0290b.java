package androidx.fragment.app;

import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import android.util.Log;
import androidx.fragment.app.F;
import androidx.lifecycle.f;
import java.util.ArrayList;

/* JADX INFO: renamed from: androidx.fragment.app.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
final class C0290b implements Parcelable {
    public static final Parcelable.Creator<C0290b> CREATOR = new a();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final int[] f4901a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final ArrayList f4902b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    final int[] f4903c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    final int[] f4904d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    final int f4905e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    final String f4906f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    final int f4907g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    final int f4908h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    final CharSequence f4909i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    final int f4910j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    final CharSequence f4911k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    final ArrayList f4912l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    final ArrayList f4913m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    final boolean f4914n;

    /* JADX INFO: renamed from: androidx.fragment.app.b$a */
    class a implements Parcelable.Creator {
        a() {
        }

        @Override // android.os.Parcelable.Creator
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public C0290b createFromParcel(Parcel parcel) {
            return new C0290b(parcel);
        }

        @Override // android.os.Parcelable.Creator
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public C0290b[] newArray(int i3) {
            return new C0290b[i3];
        }
    }

    C0290b(C0289a c0289a) {
        int size = c0289a.f4728c.size();
        this.f4901a = new int[size * 6];
        if (!c0289a.f4734i) {
            throw new IllegalStateException("Not on back stack");
        }
        this.f4902b = new ArrayList(size);
        this.f4903c = new int[size];
        this.f4904d = new int[size];
        int i3 = 0;
        for (int i4 = 0; i4 < size; i4++) {
            F.a aVar = (F.a) c0289a.f4728c.get(i4);
            int i5 = i3 + 1;
            this.f4901a[i3] = aVar.f4745a;
            ArrayList arrayList = this.f4902b;
            Fragment fragment = aVar.f4746b;
            arrayList.add(fragment != null ? fragment.f4788g : null);
            int[] iArr = this.f4901a;
            iArr[i5] = aVar.f4747c ? 1 : 0;
            iArr[i3 + 2] = aVar.f4748d;
            iArr[i3 + 3] = aVar.f4749e;
            int i6 = i3 + 5;
            iArr[i3 + 4] = aVar.f4750f;
            i3 += 6;
            iArr[i6] = aVar.f4751g;
            this.f4903c[i4] = aVar.f4752h.ordinal();
            this.f4904d[i4] = aVar.f4753i.ordinal();
        }
        this.f4905e = c0289a.f4733h;
        this.f4906f = c0289a.f4736k;
        this.f4907g = c0289a.f4899v;
        this.f4908h = c0289a.f4737l;
        this.f4909i = c0289a.f4738m;
        this.f4910j = c0289a.f4739n;
        this.f4911k = c0289a.f4740o;
        this.f4912l = c0289a.f4741p;
        this.f4913m = c0289a.f4742q;
        this.f4914n = c0289a.f4743r;
    }

    private void a(C0289a c0289a) {
        int i3 = 0;
        int i4 = 0;
        while (true) {
            boolean z3 = true;
            if (i3 >= this.f4901a.length) {
                c0289a.f4733h = this.f4905e;
                c0289a.f4736k = this.f4906f;
                c0289a.f4734i = true;
                c0289a.f4737l = this.f4908h;
                c0289a.f4738m = this.f4909i;
                c0289a.f4739n = this.f4910j;
                c0289a.f4740o = this.f4911k;
                c0289a.f4741p = this.f4912l;
                c0289a.f4742q = this.f4913m;
                c0289a.f4743r = this.f4914n;
                return;
            }
            F.a aVar = new F.a();
            int i5 = i3 + 1;
            aVar.f4745a = this.f4901a[i3];
            if (x.G0(2)) {
                Log.v("FragmentManager", "Instantiate " + c0289a + " op #" + i4 + " base fragment #" + this.f4901a[i5]);
            }
            aVar.f4752h = f.b.values()[this.f4903c[i4]];
            aVar.f4753i = f.b.values()[this.f4904d[i4]];
            int[] iArr = this.f4901a;
            int i6 = i3 + 2;
            if (iArr[i5] == 0) {
                z3 = false;
            }
            aVar.f4747c = z3;
            int i7 = iArr[i6];
            aVar.f4748d = i7;
            int i8 = iArr[i3 + 3];
            aVar.f4749e = i8;
            int i9 = i3 + 5;
            int i10 = iArr[i3 + 4];
            aVar.f4750f = i10;
            i3 += 6;
            int i11 = iArr[i9];
            aVar.f4751g = i11;
            c0289a.f4729d = i7;
            c0289a.f4730e = i8;
            c0289a.f4731f = i10;
            c0289a.f4732g = i11;
            c0289a.e(aVar);
            i4++;
        }
    }

    public C0289a b(x xVar) {
        C0289a c0289a = new C0289a(xVar);
        a(c0289a);
        c0289a.f4899v = this.f4907g;
        for (int i3 = 0; i3 < this.f4902b.size(); i3++) {
            String str = (String) this.f4902b.get(i3);
            if (str != null) {
                ((F.a) c0289a.f4728c.get(i3)).f4746b = xVar.e0(str);
            }
        }
        c0289a.n(1);
        return c0289a;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i3) {
        parcel.writeIntArray(this.f4901a);
        parcel.writeStringList(this.f4902b);
        parcel.writeIntArray(this.f4903c);
        parcel.writeIntArray(this.f4904d);
        parcel.writeInt(this.f4905e);
        parcel.writeString(this.f4906f);
        parcel.writeInt(this.f4907g);
        parcel.writeInt(this.f4908h);
        TextUtils.writeToParcel(this.f4909i, parcel, 0);
        parcel.writeInt(this.f4910j);
        TextUtils.writeToParcel(this.f4911k, parcel, 0);
        parcel.writeStringList(this.f4912l);
        parcel.writeStringList(this.f4913m);
        parcel.writeInt(this.f4914n ? 1 : 0);
    }

    C0290b(Parcel parcel) {
        this.f4901a = parcel.createIntArray();
        this.f4902b = parcel.createStringArrayList();
        this.f4903c = parcel.createIntArray();
        this.f4904d = parcel.createIntArray();
        this.f4905e = parcel.readInt();
        this.f4906f = parcel.readString();
        this.f4907g = parcel.readInt();
        this.f4908h = parcel.readInt();
        Parcelable.Creator creator = TextUtils.CHAR_SEQUENCE_CREATOR;
        this.f4909i = (CharSequence) creator.createFromParcel(parcel);
        this.f4910j = parcel.readInt();
        this.f4911k = (CharSequence) creator.createFromParcel(parcel);
        this.f4912l = parcel.createStringArrayList();
        this.f4913m = parcel.createStringArrayList();
        this.f4914n = parcel.readInt() != 0;
    }
}

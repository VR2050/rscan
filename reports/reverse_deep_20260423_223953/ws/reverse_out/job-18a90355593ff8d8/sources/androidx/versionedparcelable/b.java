package androidx.versionedparcelable;

import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import android.util.SparseIntArray;
import l.C0606a;

/* JADX INFO: loaded from: classes.dex */
class b extends a {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final SparseIntArray f5379d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Parcel f5380e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final int f5381f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final int f5382g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final String f5383h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f5384i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f5385j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private int f5386k;

    b(Parcel parcel) {
        this(parcel, parcel.dataPosition(), parcel.dataSize(), "", new C0606a(), new C0606a(), new C0606a());
    }

    @Override // androidx.versionedparcelable.a
    public void A(byte[] bArr) {
        if (bArr == null) {
            this.f5380e.writeInt(-1);
        } else {
            this.f5380e.writeInt(bArr.length);
            this.f5380e.writeByteArray(bArr);
        }
    }

    @Override // androidx.versionedparcelable.a
    protected void C(CharSequence charSequence) {
        TextUtils.writeToParcel(charSequence, this.f5380e, 0);
    }

    @Override // androidx.versionedparcelable.a
    public void E(int i3) {
        this.f5380e.writeInt(i3);
    }

    @Override // androidx.versionedparcelable.a
    public void G(Parcelable parcelable) {
        this.f5380e.writeParcelable(parcelable, 0);
    }

    @Override // androidx.versionedparcelable.a
    public void I(String str) {
        this.f5380e.writeString(str);
    }

    @Override // androidx.versionedparcelable.a
    public void a() {
        int i3 = this.f5384i;
        if (i3 >= 0) {
            int i4 = this.f5379d.get(i3);
            int iDataPosition = this.f5380e.dataPosition();
            this.f5380e.setDataPosition(i4);
            this.f5380e.writeInt(iDataPosition - i4);
            this.f5380e.setDataPosition(iDataPosition);
        }
    }

    @Override // androidx.versionedparcelable.a
    protected a b() {
        Parcel parcel = this.f5380e;
        int iDataPosition = parcel.dataPosition();
        int i3 = this.f5385j;
        if (i3 == this.f5381f) {
            i3 = this.f5382g;
        }
        return new b(parcel, iDataPosition, i3, this.f5383h + "  ", this.f5376a, this.f5377b, this.f5378c);
    }

    @Override // androidx.versionedparcelable.a
    public boolean g() {
        return this.f5380e.readInt() != 0;
    }

    @Override // androidx.versionedparcelable.a
    public byte[] i() {
        int i3 = this.f5380e.readInt();
        if (i3 < 0) {
            return null;
        }
        byte[] bArr = new byte[i3];
        this.f5380e.readByteArray(bArr);
        return bArr;
    }

    @Override // androidx.versionedparcelable.a
    protected CharSequence k() {
        return (CharSequence) TextUtils.CHAR_SEQUENCE_CREATOR.createFromParcel(this.f5380e);
    }

    @Override // androidx.versionedparcelable.a
    public boolean m(int i3) {
        while (this.f5385j < this.f5382g) {
            int i4 = this.f5386k;
            if (i4 == i3) {
                return true;
            }
            if (String.valueOf(i4).compareTo(String.valueOf(i3)) > 0) {
                return false;
            }
            this.f5380e.setDataPosition(this.f5385j);
            int i5 = this.f5380e.readInt();
            this.f5386k = this.f5380e.readInt();
            this.f5385j += i5;
        }
        return this.f5386k == i3;
    }

    @Override // androidx.versionedparcelable.a
    public int o() {
        return this.f5380e.readInt();
    }

    @Override // androidx.versionedparcelable.a
    public Parcelable q() {
        return this.f5380e.readParcelable(getClass().getClassLoader());
    }

    @Override // androidx.versionedparcelable.a
    public String s() {
        return this.f5380e.readString();
    }

    @Override // androidx.versionedparcelable.a
    public void w(int i3) {
        a();
        this.f5384i = i3;
        this.f5379d.put(i3, this.f5380e.dataPosition());
        E(0);
        E(i3);
    }

    @Override // androidx.versionedparcelable.a
    public void y(boolean z3) {
        this.f5380e.writeInt(z3 ? 1 : 0);
    }

    private b(Parcel parcel, int i3, int i4, String str, C0606a c0606a, C0606a c0606a2, C0606a c0606a3) {
        super(c0606a, c0606a2, c0606a3);
        this.f5379d = new SparseIntArray();
        this.f5384i = -1;
        this.f5386k = -1;
        this.f5380e = parcel;
        this.f5381f = i3;
        this.f5382g = i4;
        this.f5385j = i3;
        this.f5383h = str;
    }
}

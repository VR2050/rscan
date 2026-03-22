package p403d.p404a.p405a.p409c;

import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.support.v4.os.ResultReceiver;

/* renamed from: d.a.a.c.a */
/* loaded from: classes.dex */
public interface InterfaceC4196a extends IInterface {

    /* renamed from: d.a.a.c.a$a */
    public static abstract class a extends Binder implements InterfaceC4196a {

        /* renamed from: a */
        public static final /* synthetic */ int f10942a = 0;

        /* renamed from: d.a.a.c.a$a$a, reason: collision with other inner class name */
        public static class C5131a implements InterfaceC4196a {

            /* renamed from: a */
            public IBinder f10943a;

            public C5131a(IBinder iBinder) {
                this.f10943a = iBinder;
            }

            @Override // p403d.p404a.p405a.p409c.InterfaceC4196a
            /* renamed from: V */
            public void mo109V(int i2, Bundle bundle) {
                Parcel obtain = Parcel.obtain();
                try {
                    obtain.writeInterfaceToken("android.support.v4.os.IResultReceiver");
                    obtain.writeInt(i2);
                    if (bundle != null) {
                        obtain.writeInt(1);
                        bundle.writeToParcel(obtain, 0);
                    } else {
                        obtain.writeInt(0);
                    }
                    if (!this.f10943a.transact(1, obtain, null, 1)) {
                        int i3 = a.f10942a;
                    }
                } finally {
                    obtain.recycle();
                }
            }

            @Override // android.os.IInterface
            public IBinder asBinder() {
                return this.f10943a;
            }
        }

        public a() {
            attachInterface(this, "android.support.v4.os.IResultReceiver");
        }

        @Override // android.os.IInterface
        public IBinder asBinder() {
            return this;
        }

        @Override // android.os.Binder
        public boolean onTransact(int i2, Parcel parcel, Parcel parcel2, int i3) {
            if (i2 == 1) {
                parcel.enforceInterface("android.support.v4.os.IResultReceiver");
                ((ResultReceiver.BinderC0033b) this).mo109V(parcel.readInt(), parcel.readInt() != 0 ? (Bundle) Bundle.CREATOR.createFromParcel(parcel) : null);
                return true;
            }
            if (i2 != 1598968902) {
                return super.onTransact(i2, parcel, parcel2, i3);
            }
            parcel2.writeString("android.support.v4.os.IResultReceiver");
            return true;
        }
    }

    /* renamed from: V */
    void mo109V(int i2, Bundle bundle);
}

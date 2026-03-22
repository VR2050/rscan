package p403d.p404a.p405a.p406a;

import android.app.Notification;
import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;

/* renamed from: d.a.a.a.a */
/* loaded from: classes.dex */
public interface InterfaceC4182a extends IInterface {

    /* renamed from: d.a.a.a.a$a */
    public static abstract class a extends Binder implements InterfaceC4182a {
        private static final String DESCRIPTOR = "android.support.v4.app.INotificationSideChannel";
        public static final int TRANSACTION_cancel = 2;
        public static final int TRANSACTION_cancelAll = 3;
        public static final int TRANSACTION_notify = 1;

        /* renamed from: d.a.a.a.a$a$a, reason: collision with other inner class name */
        public static class C5128a implements InterfaceC4182a {

            /* renamed from: a */
            public static InterfaceC4182a f10927a;

            /* renamed from: b */
            public IBinder f10928b;

            public C5128a(IBinder iBinder) {
                this.f10928b = iBinder;
            }

            @Override // android.os.IInterface
            public IBinder asBinder() {
                return this.f10928b;
            }

            @Override // p403d.p404a.p405a.p406a.InterfaceC4182a
            public void cancel(String str, int i2, String str2) {
                Parcel obtain = Parcel.obtain();
                try {
                    obtain.writeInterfaceToken(a.DESCRIPTOR);
                    obtain.writeString(str);
                    obtain.writeInt(i2);
                    obtain.writeString(str2);
                    if (this.f10928b.transact(2, obtain, null, 1) || a.getDefaultImpl() == null) {
                        return;
                    }
                    a.getDefaultImpl().cancel(str, i2, str2);
                } finally {
                    obtain.recycle();
                }
            }

            @Override // p403d.p404a.p405a.p406a.InterfaceC4182a
            public void cancelAll(String str) {
                Parcel obtain = Parcel.obtain();
                try {
                    obtain.writeInterfaceToken(a.DESCRIPTOR);
                    obtain.writeString(str);
                    if (this.f10928b.transact(3, obtain, null, 1) || a.getDefaultImpl() == null) {
                        return;
                    }
                    a.getDefaultImpl().cancelAll(str);
                } finally {
                    obtain.recycle();
                }
            }

            @Override // p403d.p404a.p405a.p406a.InterfaceC4182a
            public void notify(String str, int i2, String str2, Notification notification) {
                Parcel obtain = Parcel.obtain();
                try {
                    obtain.writeInterfaceToken(a.DESCRIPTOR);
                    obtain.writeString(str);
                    obtain.writeInt(i2);
                    obtain.writeString(str2);
                    if (notification != null) {
                        obtain.writeInt(1);
                        notification.writeToParcel(obtain, 0);
                    } else {
                        obtain.writeInt(0);
                    }
                    if (this.f10928b.transact(1, obtain, null, 1) || a.getDefaultImpl() == null) {
                        return;
                    }
                    a.getDefaultImpl().notify(str, i2, str2, notification);
                } finally {
                    obtain.recycle();
                }
            }
        }

        public a() {
            attachInterface(this, DESCRIPTOR);
        }

        public static InterfaceC4182a asInterface(IBinder iBinder) {
            if (iBinder == null) {
                return null;
            }
            IInterface queryLocalInterface = iBinder.queryLocalInterface(DESCRIPTOR);
            return (queryLocalInterface == null || !(queryLocalInterface instanceof InterfaceC4182a)) ? new C5128a(iBinder) : (InterfaceC4182a) queryLocalInterface;
        }

        public static InterfaceC4182a getDefaultImpl() {
            return C5128a.f10927a;
        }

        public static boolean setDefaultImpl(InterfaceC4182a interfaceC4182a) {
            if (C5128a.f10927a != null) {
                throw new IllegalStateException("setDefaultImpl() called twice");
            }
            if (interfaceC4182a == null) {
                return false;
            }
            C5128a.f10927a = interfaceC4182a;
            return true;
        }

        @Override // android.os.IInterface
        public IBinder asBinder() {
            return this;
        }

        @Override // android.os.Binder
        public boolean onTransact(int i2, Parcel parcel, Parcel parcel2, int i3) {
            if (i2 == 1) {
                parcel.enforceInterface(DESCRIPTOR);
                notify(parcel.readString(), parcel.readInt(), parcel.readString(), parcel.readInt() != 0 ? (Notification) Notification.CREATOR.createFromParcel(parcel) : null);
                return true;
            }
            if (i2 == 2) {
                parcel.enforceInterface(DESCRIPTOR);
                cancel(parcel.readString(), parcel.readInt(), parcel.readString());
                return true;
            }
            if (i2 == 3) {
                parcel.enforceInterface(DESCRIPTOR);
                cancelAll(parcel.readString());
                return true;
            }
            if (i2 != 1598968902) {
                return super.onTransact(i2, parcel, parcel2, i3);
            }
            parcel2.writeString(DESCRIPTOR);
            return true;
        }
    }

    void cancel(String str, int i2, String str2);

    void cancelAll(String str);

    void notify(String str, int i2, String str2, Notification notification);
}

package android.support.v4.os;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;
import androidx.annotation.RestrictTo;
import java.util.Objects;
import p403d.p404a.p405a.p409c.InterfaceC4196a;

@SuppressLint({"BanParcelableUsage"})
@RestrictTo({RestrictTo.Scope.LIBRARY_GROUP_PREFIX})
/* loaded from: classes.dex */
public class ResultReceiver implements Parcelable {
    public static final Parcelable.Creator<ResultReceiver> CREATOR = new C0032a();

    /* renamed from: c */
    public InterfaceC4196a f97c;

    /* renamed from: android.support.v4.os.ResultReceiver$a */
    public class C0032a implements Parcelable.Creator<ResultReceiver> {
        @Override // android.os.Parcelable.Creator
        public ResultReceiver createFromParcel(Parcel parcel) {
            return new ResultReceiver(parcel);
        }

        @Override // android.os.Parcelable.Creator
        public ResultReceiver[] newArray(int i2) {
            return new ResultReceiver[i2];
        }
    }

    /* renamed from: android.support.v4.os.ResultReceiver$b */
    public class BinderC0033b extends InterfaceC4196a.a {
        public BinderC0033b() {
        }

        @Override // p403d.p404a.p405a.p409c.InterfaceC4196a
        /* renamed from: V */
        public void mo109V(int i2, Bundle bundle) {
            Objects.requireNonNull(ResultReceiver.this);
            ResultReceiver.this.mo2b(i2, bundle);
        }
    }

    public ResultReceiver(Parcel parcel) {
        InterfaceC4196a c5131a;
        IBinder readStrongBinder = parcel.readStrongBinder();
        int i2 = InterfaceC4196a.a.f10942a;
        if (readStrongBinder == null) {
            c5131a = null;
        } else {
            IInterface queryLocalInterface = readStrongBinder.queryLocalInterface("android.support.v4.os.IResultReceiver");
            c5131a = (queryLocalInterface == null || !(queryLocalInterface instanceof InterfaceC4196a)) ? new InterfaceC4196a.a.C5131a(readStrongBinder) : (InterfaceC4196a) queryLocalInterface;
        }
        this.f97c = c5131a;
    }

    /* renamed from: b */
    public void mo2b(int i2, Bundle bundle) {
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    /* renamed from: e */
    public void m108e(int i2, Bundle bundle) {
        InterfaceC4196a interfaceC4196a = this.f97c;
        if (interfaceC4196a != null) {
            try {
                interfaceC4196a.mo109V(i2, bundle);
            } catch (RemoteException unused) {
            }
        }
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        synchronized (this) {
            if (this.f97c == null) {
                this.f97c = new BinderC0033b();
            }
            parcel.writeStrongBinder(this.f97c.asBinder());
        }
    }
}

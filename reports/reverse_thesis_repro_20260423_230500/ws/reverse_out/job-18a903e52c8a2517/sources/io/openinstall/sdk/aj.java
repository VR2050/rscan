package io.openinstall.sdk;

import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;

/* JADX INFO: loaded from: classes3.dex */
public class aj implements z {

    private static final class a implements IInterface {
        private final IBinder a;

        public a(IBinder iBinder) {
            this.a = iBinder;
        }

        public String a() throws RemoteException {
            Parcel parcelObtain = Parcel.obtain();
            Parcel parcelObtain2 = Parcel.obtain();
            try {
                parcelObtain.writeInterfaceToken("com.samsung.android.deviceidservice.IDeviceIdService");
                this.a.transact(1, parcelObtain, parcelObtain2, 0);
                parcelObtain2.readException();
                return parcelObtain2.readString();
            } finally {
                parcelObtain.recycle();
                parcelObtain2.recycle();
            }
        }

        @Override // android.os.IInterface
        public IBinder asBinder() {
            return this.a;
        }
    }

    @Override // io.openinstall.sdk.z
    public String a(Context context) {
        Intent intent = new Intent();
        intent.setClassName("com.samsung.android.deviceidservice", "com.samsung.android.deviceidservice.DeviceIdService");
        x xVar = new x();
        if (context.bindService(intent, xVar, 1)) {
            try {
                String strA = new a(xVar.a()).a();
                context.unbindService(xVar);
                return strA;
            } catch (RemoteException e) {
                context.unbindService(xVar);
                return null;
            } catch (InterruptedException e2) {
                context.unbindService(xVar);
                return null;
            } catch (Throwable th) {
                context.unbindService(xVar);
                throw th;
            }
        }
        return null;
    }
}

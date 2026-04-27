package io.openinstall.sdk;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;

/* JADX INFO: loaded from: classes3.dex */
public class ac implements z {

    private static final class a implements IInterface {
        private final IBinder a;

        public a(IBinder iBinder) {
            this.a = iBinder;
        }

        public String a(String str) throws RemoteException {
            Parcel parcelObtain = Parcel.obtain();
            Parcel parcelObtain2 = Parcel.obtain();
            try {
                parcelObtain.writeInterfaceToken("com.coolpad.deviceidsupport.IDeviceIdManager");
                parcelObtain.writeString(str);
                this.a.transact(2, parcelObtain, parcelObtain2, 0);
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
        intent.setComponent(new ComponentName("com.coolpad.deviceidsupport", "com.coolpad.deviceidsupport.DeviceIdService"));
        x xVar = new x();
        if (context.bindService(intent, xVar, 1)) {
            try {
                String strA = new a(xVar.a()).a(context.getPackageName());
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

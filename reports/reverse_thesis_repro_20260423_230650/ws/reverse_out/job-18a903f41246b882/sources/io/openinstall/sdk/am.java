package io.openinstall.sdk;

import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;

/* JADX INFO: loaded from: classes3.dex */
public class am implements z {

    private static final class a implements IInterface {
        private final IBinder a;

        public a(IBinder iBinder) {
            this.a = iBinder;
        }

        public String a() throws RemoteException {
            Parcel parcelObtain = Parcel.obtain();
            Parcel parcelObtain2 = Parcel.obtain();
            try {
                parcelObtain.writeInterfaceToken("com.bun.lib.MsaIdInterface");
                this.a.transact(3, parcelObtain, parcelObtain2, 0);
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
        intent.setClassName("com.mdid.msa", "com.mdid.msa.service.MsaKlService");
        intent.setAction("com.bun.msa.action.start.service");
        intent.putExtra("com.bun.msa.param.pkgname", context.getPackageName());
        intent.putExtra("com.bun.msa.param.runinset", true);
        try {
            context.startService(intent);
        } catch (Exception e) {
        }
        x xVar = new x();
        Intent intent2 = new Intent();
        intent2.setClassName("com.mdid.msa", "com.mdid.msa.service.MsaIdService");
        intent2.setAction("com.bun.msa.action.bindto.service");
        intent2.putExtra("com.bun.msa.param.pkgname", context.getPackageName());
        if (context.bindService(intent2, xVar, 1)) {
            try {
                String strA = new a(xVar.a()).a();
                context.unbindService(xVar);
                return strA;
            } catch (RemoteException e2) {
                context.unbindService(xVar);
                return null;
            } catch (InterruptedException e3) {
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

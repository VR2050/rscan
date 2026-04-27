package io.openinstall.sdk;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.provider.Settings;
import android.text.TextUtils;

/* JADX INFO: loaded from: classes3.dex */
public class ae implements z {

    private static final class a implements IInterface {
        private final IBinder a;

        public a(IBinder iBinder) {
            this.a = iBinder;
        }

        public String a() throws RemoteException {
            Parcel parcelObtain = Parcel.obtain();
            Parcel parcelObtain2 = Parcel.obtain();
            try {
                parcelObtain.writeInterfaceToken("com.uodis.opendevice.aidl.OpenDeviceIdentifierService");
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
        String string = null;
        if (Build.VERSION.SDK_INT >= 24) {
            try {
                string = Settings.Global.getString(context.getContentResolver(), "pps_oaid");
                if (!TextUtils.isEmpty(string)) {
                    return string;
                }
            } catch (Throwable th) {
            }
        }
        Intent intent = new Intent("com.uodis.opendevice.OPENIDS_SERVICE");
        intent.setPackage("com.huawei.hwid");
        x xVar = new x();
        if (context.bindService(intent, xVar, 1)) {
            try {
                string = new a(xVar.a()).a();
            } catch (RemoteException e) {
            } catch (InterruptedException e2) {
            } catch (Throwable th2) {
                context.unbindService(xVar);
                throw th2;
            }
            context.unbindService(xVar);
        }
        return string;
    }
}

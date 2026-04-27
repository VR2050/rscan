package io.openinstall.sdk;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import kotlin.UByte;

/* JADX INFO: loaded from: classes3.dex */
public class ai implements z {
    private final Context a;
    private String b;

    private static final class a implements IInterface {
        private final IBinder a;

        public a(IBinder iBinder) {
            this.a = iBinder;
        }

        public String a(String str, String str2, String str3) throws RemoteException {
            Parcel parcelObtain = Parcel.obtain();
            Parcel parcelObtain2 = Parcel.obtain();
            try {
                parcelObtain.writeInterfaceToken("com.heytap.openid.IOpenID");
                parcelObtain.writeString(str);
                parcelObtain.writeString(str2);
                parcelObtain.writeString(str3);
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

    public ai(Context context) {
        this.a = context;
    }

    private String a() throws NoSuchAlgorithmException, PackageManager.NameNotFoundException {
        if (this.b == null) {
            byte[] bArrDigest = MessageDigest.getInstance("SHA1").digest(this.a.getPackageManager().getPackageInfo(this.a.getPackageName(), 64).signatures[0].toByteArray());
            StringBuilder sb = new StringBuilder();
            for (byte b : bArrDigest) {
                sb.append(Integer.toHexString((b & UByte.MAX_VALUE) | 256).substring(1, 3));
            }
            this.b = sb.toString();
        }
        return this.b;
    }

    @Override // io.openinstall.sdk.z
    public String a(Context context) {
        Intent intent = new Intent("action.com.heytap.openid.OPEN_ID_SERVICE");
        intent.setComponent(new ComponentName("com.heytap.openid", "com.heytap.openid.IdentifyService"));
        x xVar = new x();
        if (context.bindService(intent, xVar, 1)) {
            try {
                String strA = new a(xVar.a()).a(context.getPackageName(), a(), "OUID");
                context.unbindService(xVar);
                return strA;
            } catch (PackageManager.NameNotFoundException e) {
                context.unbindService(xVar);
                return null;
            } catch (RemoteException e2) {
                context.unbindService(xVar);
                return null;
            } catch (InterruptedException e3) {
                context.unbindService(xVar);
                return null;
            } catch (NoSuchAlgorithmException e4) {
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

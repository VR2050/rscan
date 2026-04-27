package com.snail.antifake.deviceid.deviceid;

import android.content.Context;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import com.snail.antifake.deviceid.BinderUtil;
import java.lang.reflect.Method;

/* JADX INFO: loaded from: classes3.dex */
public class IPhoneSubInfoUtil {
    public static String getDeviceId(Context context) throws RemoteException {
        String deviceIdLevel2 = getDeviceIdLevel2(context);
        String deviceId = deviceIdLevel2;
        if (TextUtils.isEmpty(deviceIdLevel2)) {
            String deviceIdLevel1 = getDeviceIdLevel1(context);
            deviceId = deviceIdLevel1;
            if (TextUtils.isEmpty(deviceIdLevel1)) {
                String deviceIdLevel0 = getDeviceIdLevel0(context);
                deviceId = deviceIdLevel0;
                if (TextUtils.isEmpty(deviceIdLevel0)) {
                    return deviceId;
                }
            }
        }
        return deviceId;
    }

    public static String getDeviceIdLevel0(Context context) {
        TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
        try {
            Method method = TelephonyManager.class.getDeclaredMethod("getSubscriberInfo", new Class[0]);
            method.setAccessible(true);
            Object binderProxy = method.invoke(telephonyManager, new Object[0]);
            try {
                Method getDeviceId = binderProxy.getClass().getDeclaredMethod("getDeviceId", String.class);
                if (getDeviceId != null) {
                    return (String) getDeviceId.invoke(binderProxy, context.getPackageName());
                }
            } catch (Exception e) {
            }
            Method getDeviceId2 = binderProxy.getClass().getDeclaredMethod("getDeviceId", new Class[0]);
            if (getDeviceId2 != null) {
                return (String) getDeviceId2.invoke(binderProxy, new Object[0]);
            }
            return "";
        } catch (Exception e2) {
            return "";
        }
    }

    public static String getDeviceIdLevel1(Context context) {
        try {
            Method getService = Class.forName("android.os.ServiceManager").getDeclaredMethod("getService", String.class);
            getService.setAccessible(true);
            IBinder binder = (IBinder) getService.invoke(null, "iphonesubinfo");
            Method asInterface = Class.forName("com.android.internal.telephony.IPhoneSubInfo$Stub").getDeclaredMethod("asInterface", IBinder.class);
            asInterface.setAccessible(true);
            Object binderProxy = asInterface.invoke(null, binder);
            try {
                Method getDeviceId = binderProxy.getClass().getDeclaredMethod("getDeviceId", String.class);
                if (getDeviceId != null) {
                    return (String) getDeviceId.invoke(binderProxy, context.getPackageName());
                }
            } catch (Exception e) {
            }
            Method getDeviceId2 = binderProxy.getClass().getDeclaredMethod("getDeviceId", new Class[0]);
            if (getDeviceId2 != null) {
                return (String) getDeviceId2.invoke(binderProxy, new Object[0]);
            }
            return "";
        } catch (Exception e2) {
            return "";
        }
    }

    public static String getDeviceIdLevel2(Context context) throws RemoteException {
        String deviceId = "";
        try {
            Method getService = Class.forName("android.os.ServiceManager").getDeclaredMethod("getService", String.class);
            getService.setAccessible(true);
            IBinder binder = (IBinder) getService.invoke(null, "iphonesubinfo");
            Method asInterface = Class.forName("com.android.internal.telephony.IPhoneSubInfo$Stub").getDeclaredMethod("asInterface", IBinder.class);
            asInterface.setAccessible(true);
            Object binderProxy = asInterface.invoke(null, binder);
            try {
                Method getDeviceId = binderProxy.getClass().getDeclaredMethod("getDeviceId", String.class);
                if (getDeviceId != null) {
                    deviceId = binderGetHardwareInfo(context.getPackageName(), binder, BinderUtil.getInterfaceDescriptor(binderProxy), BinderUtil.getTransactionId(binderProxy, "TRANSACTION_getDeviceId"));
                }
            } catch (Exception e) {
            }
            Method getDeviceId2 = binderProxy.getClass().getDeclaredMethod("getDeviceId", new Class[0]);
            if (getDeviceId2 != null) {
                return binderGetHardwareInfo("", binder, BinderUtil.getInterfaceDescriptor(binderProxy), BinderUtil.getTransactionId(binderProxy, "TRANSACTION_getDeviceId"));
            }
            return deviceId;
        } catch (Exception e2) {
            return deviceId;
        }
    }

    private static String binderGetHardwareInfo(String callingPackage, IBinder remote, String DESCRIPTOR, int tid) throws RemoteException {
        Parcel _data = Parcel.obtain();
        Parcel _reply = Parcel.obtain();
        try {
            _data.writeInterfaceToken(DESCRIPTOR);
            if (!TextUtils.isEmpty(callingPackage)) {
                _data.writeString(callingPackage);
            }
            remote.transact(tid, _data, _reply, 0);
            _reply.readException();
            String _result = _reply.readString();
            return _result;
        } finally {
            _reply.recycle();
            _data.recycle();
        }
    }
}

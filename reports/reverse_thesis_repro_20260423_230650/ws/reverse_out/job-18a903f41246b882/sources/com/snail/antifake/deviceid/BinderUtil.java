package com.snail.antifake.deviceid;

import android.os.RemoteException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/* JADX INFO: loaded from: classes3.dex */
public class BinderUtil {
    public static int getTransactionId(Object proxy, String name) throws IllegalAccessException, NoSuchFieldException, RemoteException {
        Field idField = proxy.getClass().getEnclosingClass().getDeclaredField(name);
        idField.setAccessible(true);
        int transactionId = ((Integer) idField.get(proxy)).intValue();
        return transactionId;
    }

    public static String getInterfaceDescriptor(Object proxy) throws IllegalAccessException, NoSuchMethodException, InvocationTargetException {
        Method getInterfaceDescriptor = proxy.getClass().getDeclaredMethod("getInterfaceDescriptor", new Class[0]);
        return (String) getInterfaceDescriptor.invoke(proxy, new Object[0]);
    }
}

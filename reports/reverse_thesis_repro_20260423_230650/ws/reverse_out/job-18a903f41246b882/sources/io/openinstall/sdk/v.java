package io.openinstall.sdk;

import android.content.Context;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes3.dex */
public class v {
    private static final CountDownLatch a = new CountDownLatch(1);
    private static String b;
    private static Object c;

    static class a implements InvocationHandler {
        a() {
        }

        @Override // java.lang.reflect.InvocationHandler
        public Object invoke(Object obj, Method method, Object[] objArr) throws Throwable {
            if (!"onInstallReferrerSetupFinished".equalsIgnoreCase(method.getName())) {
                if ("onInstallReferrerServiceDisconnected".equalsIgnoreCase(method.getName())) {
                    if (!ec.a) {
                        return null;
                    }
                    ec.a("StateListenerHandler : InstallReferrerService Disconnected", new Object[0]);
                    return null;
                }
                if (!ec.a) {
                    return null;
                }
                ec.a("StateListenerHandler : no such method : " + method.getName(), new Object[0]);
                return null;
            }
            try {
                int iIntValue = ((Integer) objArr[0]).intValue();
                if (ec.a) {
                    ec.a("StateListenerHandler : onInstallReferrerSetupFinished code=" + iIntValue, new Object[0]);
                }
                if (iIntValue == 0) {
                    Class<?> cls = Class.forName("com.android.installreferrer.api.InstallReferrerClient");
                    String unused = v.b = (String) Class.forName("com.android.installreferrer.api.ReferrerDetails").getDeclaredMethod("getInstallReferrer", new Class[0]).invoke(cls.getDeclaredMethod("getInstallReferrer", new Class[0]).invoke(v.c, new Object[0]), new Object[0]);
                    cls.getDeclaredMethod("endConnection", new Class[0]).invoke(v.c, new Object[0]);
                }
            } catch (Throwable th) {
                if (ec.a) {
                    ec.a("InstallReferrerClient getInstallReferrer failed", new Object[0]);
                }
            }
            v.a.countDown();
            return null;
        }
    }

    public String a() {
        try {
            a.await(3L, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
        }
        if (ec.a) {
            ec.a("PlayInstallReferrer getReferrer : %s", b);
        }
        return b;
    }

    public void a(Context context) {
        try {
            Class<?> cls = Class.forName("com.android.installreferrer.api.InstallReferrerClient");
            c = Class.forName("com.android.installreferrer.api.InstallReferrerClient$Builder").getDeclaredMethod("build", new Class[0]).invoke(cls.getDeclaredMethod("newBuilder", Context.class).invoke(null, context), new Object[0]);
            Class<?> cls2 = Class.forName("com.android.installreferrer.api.InstallReferrerStateListener");
            cls.getDeclaredMethod("startConnection", cls2).invoke(c, Proxy.newProxyInstance(context.getClassLoader(), new Class[]{cls2}, new a()));
        } catch (Throwable th) {
            a.countDown();
            if (ec.a) {
                ec.b("InstallReferrerClient Connection Failed", new Object[0]);
            }
        }
    }
}

package io.openinstall.sdk;

import android.content.Context;
import java.lang.reflect.InvocationTargetException;

/* JADX INFO: loaded from: classes3.dex */
public class al implements z {
    @Override // io.openinstall.sdk.z
    public String a(Context context) {
        try {
            Class<?> cls = Class.forName("com.android.id.impl.IdProviderImpl");
            Object objInvoke = cls.getMethod("getOAID", Context.class).invoke(cls.newInstance(), context);
            if (objInvoke != null) {
                return (String) objInvoke;
            }
            return null;
        } catch (ClassNotFoundException e) {
            return null;
        } catch (IllegalAccessException e2) {
            return null;
        } catch (InstantiationException e3) {
            return null;
        } catch (NoSuchMethodException e4) {
            return null;
        } catch (InvocationTargetException e5) {
            return null;
        }
    }
}

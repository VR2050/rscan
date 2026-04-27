package com.blankj.utilcode.util;

import android.util.Log;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/* JADX INFO: loaded from: classes.dex */
public final class ApiUtils {
    private static final String TAG = "ApiUtils";
    private Map<Class, BaseApi> mApiMap;
    private Map<Class, Class> mInjectApiImplMap;

    @Target({ElementType.TYPE})
    @Retention(RetentionPolicy.CLASS)
    public @interface Api {
        boolean isMock() default false;
    }

    public static abstract class BaseApi {
    }

    private ApiUtils() {
        this.mApiMap = new ConcurrentHashMap();
        this.mInjectApiImplMap = new HashMap();
        init();
    }

    private void init() {
    }

    private void registerImpl(Class implClass) {
        this.mInjectApiImplMap.put(implClass.getSuperclass(), implClass);
    }

    public static <T extends BaseApi> T getApi(Class<T> apiClass) {
        if (apiClass == null) {
            throw new NullPointerException("Argument 'apiClass' of type Class<T> (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return (T) getInstance().getApiInner(apiClass);
    }

    public static String toString_() {
        return getInstance().toString();
    }

    public String toString() {
        return "ApiUtils: " + this.mInjectApiImplMap;
    }

    private static ApiUtils getInstance() {
        return LazyHolder.INSTANCE;
    }

    private <Result> Result getApiInner(Class cls) {
        Object obj = (Result) this.mApiMap.get(cls);
        if (obj == null) {
            synchronized (this) {
                obj = this.mApiMap.get(cls);
                if (obj == null) {
                    Class cls2 = this.mInjectApiImplMap.get(cls);
                    if (cls2 != null) {
                        try {
                            obj = (Result) ((BaseApi) cls2.newInstance());
                            this.mApiMap.put(cls, (BaseApi) obj);
                        } catch (Exception e) {
                            Log.e(TAG, "The <" + cls2 + "> has no parameterless constructor.");
                            return null;
                        }
                    } else {
                        Log.e(TAG, "The <" + cls + "> doesn't implement.");
                        return null;
                    }
                }
            }
        }
        return (Result) obj;
    }

    private static class LazyHolder {
        private static final ApiUtils INSTANCE = new ApiUtils();

        private LazyHolder() {
        }
    }
}

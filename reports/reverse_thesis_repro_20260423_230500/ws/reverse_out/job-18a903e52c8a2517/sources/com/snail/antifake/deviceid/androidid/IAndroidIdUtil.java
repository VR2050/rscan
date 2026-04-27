package com.snail.antifake.deviceid.androidid;

import android.content.Context;
import android.provider.Settings;
import android.text.TextUtils;

/* JADX INFO: loaded from: classes3.dex */
public class IAndroidIdUtil {
    public static String getAndroidId(Context context) {
        String androidPropertyLevel1 = ISettingUtils.getAndroidPropertyLevel1(context, "android_id");
        String androidId = androidPropertyLevel1;
        if (TextUtils.isEmpty(androidPropertyLevel1)) {
            String androidProperty = ISettingUtils.getAndroidProperty(context, "android_id");
            androidId = androidProperty;
            if (TextUtils.isEmpty(androidProperty)) {
                return Settings.Secure.getString(context.getContentResolver(), "android_id");
            }
        }
        return androidId;
    }
}

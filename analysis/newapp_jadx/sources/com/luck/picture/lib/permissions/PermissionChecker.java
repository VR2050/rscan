package com.luck.picture.lib.permissions;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import androidx.annotation.NonNull;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import com.alibaba.fastjson.asm.Label;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class PermissionChecker {
    public static boolean checkSelfPermission(Context context, String str) {
        return ContextCompat.checkSelfPermission(context.getApplicationContext(), str) == 0;
    }

    private static boolean isIntentAvailable(Context context, Intent intent) {
        return context.getApplicationContext().getPackageManager().queryIntentActivities(intent, 65536).size() > 0;
    }

    public static void launchAppDetailsSettings(Context context) {
        Context applicationContext = context.getApplicationContext();
        Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
        StringBuilder m586H = C1499a.m586H("package:");
        m586H.append(applicationContext.getPackageName());
        intent.setData(Uri.parse(m586H.toString()));
        if (isIntentAvailable(context, intent)) {
            applicationContext.startActivity(intent.addFlags(Label.FORWARD_REFERENCE_TYPE_SHORT));
        }
    }

    public static void requestPermissions(Activity activity, @NonNull String[] strArr, int i2) {
        ActivityCompat.requestPermissions(activity, strArr, i2);
    }
}

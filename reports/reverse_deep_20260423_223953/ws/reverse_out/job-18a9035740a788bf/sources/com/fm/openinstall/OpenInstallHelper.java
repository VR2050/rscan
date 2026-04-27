package com.fm.openinstall;

import android.app.Activity;
import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.text.TextUtils;
import io.openinstall.sdk.by;
import io.openinstall.sdk.dx;
import io.openinstall.sdk.k;

/* JADX INFO: loaded from: classes.dex */
public final class OpenInstallHelper {
    private OpenInstallHelper() {
    }

    public static boolean checkSimulator(Context context) {
        return k.a().a(context);
    }

    public static boolean isLauncherFromYYB(Activity activity, Intent intent) {
        Uri referrer;
        if (activity == null || intent == null || TextUtils.isEmpty(intent.getAction()) || intent.getCategories() == null || !intent.getAction().equals("android.intent.action.MAIN") || !intent.getCategories().contains("android.intent.category.LAUNCHER") || Build.VERSION.SDK_INT < 22 || (referrer = activity.getReferrer()) == null) {
            return false;
        }
        String authority = referrer.getAuthority();
        if (TextUtils.isEmpty(authority)) {
            return false;
        }
        boolean z = authority.equalsIgnoreCase(dx.o) || authority.equalsIgnoreCase(dx.p) || authority.equalsIgnoreCase(dx.n);
        if (authority.equalsIgnoreCase(dx.q) || authority.equalsIgnoreCase(dx.r) || authority.equalsIgnoreCase(dx.s)) {
            return true;
        }
        return z;
    }

    @Deprecated
    public static boolean isSchemeWakeup(Intent intent) {
        if (intent == null || intent.getData() == null || intent.getAction() == null) {
            return false;
        }
        return !TextUtils.isEmpty(intent.getData().getHost()) && intent.getAction().equals("android.intent.action.VIEW");
    }

    public static boolean isTrackData(ClipData clipData) {
        by byVarA = by.a(clipData);
        if (byVarA == null) {
            return false;
        }
        return byVarA.c(1) || byVarA.c(2);
    }
}

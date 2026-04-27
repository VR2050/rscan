package com.google.android.exoplayer2.scheduler;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.os.PowerManager;
import androidx.core.app.NotificationCompat;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.Util;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/* JADX INFO: loaded from: classes2.dex */
public final class Requirements {
    public static final int DEVICE_CHARGING = 32;
    public static final int DEVICE_IDLE = 16;
    public static final int NETWORK_TYPE_ANY = 1;
    private static final int NETWORK_TYPE_MASK = 15;
    public static final int NETWORK_TYPE_METERED = 8;
    public static final int NETWORK_TYPE_NONE = 0;
    public static final int NETWORK_TYPE_NOT_ROAMING = 4;
    private static final String[] NETWORK_TYPE_STRINGS = null;
    public static final int NETWORK_TYPE_UNMETERED = 2;
    private static final String TAG = "Requirements";
    private final int requirements;

    @Documented
    @Retention(RetentionPolicy.SOURCE)
    public @interface NetworkType {
    }

    @Documented
    @Retention(RetentionPolicy.SOURCE)
    public @interface RequirementFlags {
    }

    public Requirements(int networkType, boolean charging, boolean idle) {
        this((idle ? 16 : 0) | (charging ? 32 : 0) | networkType);
    }

    public Requirements(int requirements) {
        this.requirements = requirements;
        int networkType = getRequiredNetworkType();
        Assertions.checkState(((networkType + (-1)) & networkType) == 0);
    }

    public int getRequiredNetworkType() {
        return this.requirements & 15;
    }

    public boolean isChargingRequired() {
        return (this.requirements & 32) != 0;
    }

    public boolean isIdleRequired() {
        return (this.requirements & 16) != 0;
    }

    public boolean checkRequirements(Context context) {
        return getNotMetRequirements(context) == 0;
    }

    public int getNotMetRequirements(Context context) {
        return (!checkNetworkRequirements(context) ? getRequiredNetworkType() : 0) | (!checkChargingRequirement(context) ? 32 : 0) | (checkIdleRequirement(context) ? 0 : 16);
    }

    public int getRequirements() {
        return this.requirements;
    }

    private boolean checkNetworkRequirements(Context context) {
        int networkRequirement = getRequiredNetworkType();
        if (networkRequirement == 0) {
            return true;
        }
        ConnectivityManager connectivityManager = (ConnectivityManager) context.getSystemService("connectivity");
        NetworkInfo networkInfo = connectivityManager.getActiveNetworkInfo();
        if (networkInfo == null || !networkInfo.isConnected()) {
            logd("No network info or no connection.");
            return false;
        }
        if (!checkInternetConnectivity(connectivityManager)) {
            return false;
        }
        if (networkRequirement == 1) {
            return true;
        }
        if (networkRequirement == 4) {
            boolean roaming = networkInfo.isRoaming();
            logd("Roaming: " + roaming);
            return !roaming;
        }
        boolean activeNetworkMetered = isActiveNetworkMetered(connectivityManager, networkInfo);
        logd("Metered network: " + activeNetworkMetered);
        if (networkRequirement == 2) {
            return !activeNetworkMetered;
        }
        if (networkRequirement == 8) {
            return activeNetworkMetered;
        }
        throw new IllegalStateException();
    }

    private boolean checkChargingRequirement(Context context) {
        if (!isChargingRequired()) {
            return true;
        }
        Intent batteryStatus = context.registerReceiver(null, new IntentFilter("android.intent.action.BATTERY_CHANGED"));
        if (batteryStatus == null) {
            return false;
        }
        int status = batteryStatus.getIntExtra(NotificationCompat.CATEGORY_STATUS, -1);
        return status == 2 || status == 5;
    }

    private boolean checkIdleRequirement(Context context) {
        if (!isIdleRequired()) {
            return true;
        }
        PowerManager powerManager = (PowerManager) context.getSystemService("power");
        if (Util.SDK_INT >= 23) {
            return powerManager.isDeviceIdleMode();
        }
        if (Util.SDK_INT >= 20) {
            if (!powerManager.isInteractive()) {
                return true;
            }
        } else if (!powerManager.isScreenOn()) {
            return true;
        }
        return false;
    }

    private static boolean checkInternetConnectivity(ConnectivityManager connectivityManager) {
        if (Util.SDK_INT < 23) {
            return true;
        }
        Network activeNetwork = connectivityManager.getActiveNetwork();
        if (activeNetwork == null) {
            logd("No active network.");
            return false;
        }
        NetworkCapabilities networkCapabilities = connectivityManager.getNetworkCapabilities(activeNetwork);
        boolean validated = networkCapabilities == null || !networkCapabilities.hasCapability(16);
        logd("Network capability validated: " + validated);
        return !validated;
    }

    private static boolean isActiveNetworkMetered(ConnectivityManager connectivityManager, NetworkInfo networkInfo) {
        if (Util.SDK_INT >= 16) {
            return connectivityManager.isActiveNetworkMetered();
        }
        int type = networkInfo.getType();
        return (type == 1 || type == 7 || type == 9) ? false : true;
    }

    private static void logd(String message) {
    }

    public String toString() {
        return super.toString();
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        return o != null && getClass() == o.getClass() && this.requirements == ((Requirements) o).requirements;
    }

    public int hashCode() {
        return this.requirements;
    }
}

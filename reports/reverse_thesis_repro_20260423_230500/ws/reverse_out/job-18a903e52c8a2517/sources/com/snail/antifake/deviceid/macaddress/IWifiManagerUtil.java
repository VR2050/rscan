package com.snail.antifake.deviceid.macaddress;

import android.content.Context;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.text.TextUtils;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/* JADX INFO: loaded from: classes3.dex */
public class IWifiManagerUtil {
    private static String INVALID_ADDRESS = "02:00:00:00:00:00";

    public static String getMacAddress(Context context) {
        String address = getMacAddressLevel1(context);
        if (!TextUtils.isEmpty(address) && !INVALID_ADDRESS.endsWith(address)) {
            return address;
        }
        String address2 = getMacAddressLevel0(context);
        return (TextUtils.isEmpty(address2) || !INVALID_ADDRESS.endsWith(address2)) ? address2 : address2;
    }

    private static String getMacAddressLevel0(Context context) {
        String macAddress = null;
        try {
            WifiManager wifiManager = (WifiManager) context.getApplicationContext().getSystemService("wifi");
            WifiInfo info = null;
            WifiInfo info2 = wifiManager == null ? null : wifiManager.getConnectionInfo();
            if (info2 != null) {
                macAddress = info2.getMacAddress();
            }
            if (!TextUtils.isEmpty(macAddress)) {
                return macAddress;
            }
            if (wifiManager != null && !wifiManager.isWifiEnabled()) {
                wifiManager.setWifiEnabled(true);
                wifiManager.setWifiEnabled(false);
            }
            if (wifiManager != null) {
                info = wifiManager.getConnectionInfo();
            }
            if (info != null) {
                return info.getMacAddress();
            }
            return macAddress;
        } catch (Exception e) {
            return macAddress;
        }
    }

    private static String getMacAddressLevel1(Context context) {
        String macAddress = null;
        try {
            WifiManager wifiManager = (WifiManager) context.getApplicationContext().getSystemService("wifi");
            Field IWifiManagerService = wifiManager.getClass().getDeclaredField("mService");
            IWifiManagerService.setAccessible(true);
            Object service = IWifiManagerService.get(wifiManager);
            Method getConnectionInfo = service.getClass().getDeclaredMethod("getConnectionInfo", new Class[0]);
            getConnectionInfo.setAccessible(true);
            WifiInfo info = (WifiInfo) getConnectionInfo.invoke(service, new Object[0]);
            if (info == null && !wifiManager.isWifiEnabled()) {
                wifiManager.setWifiEnabled(true);
                wifiManager.setWifiEnabled(false);
                info = (WifiInfo) getConnectionInfo.invoke(service, new Object[0]);
            }
            try {
                Field mMacAddress = info.getClass().getDeclaredField("mMacAddress");
                mMacAddress.setAccessible(true);
                macAddress = (String) mMacAddress.get(info);
                if (!TextUtils.isEmpty(macAddress)) {
                    return macAddress;
                }
            } catch (Exception e) {
            }
            if (info != null) {
                return info.getMacAddress();
            }
            return macAddress;
        } catch (Exception e2) {
            return macAddress;
        }
    }
}

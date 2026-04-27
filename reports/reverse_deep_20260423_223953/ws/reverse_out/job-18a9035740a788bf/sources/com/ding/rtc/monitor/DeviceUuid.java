package com.ding.rtc.monitor;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/* JADX INFO: loaded from: classes.dex */
public class DeviceUuid {
    private static final String CACHE_IMAGE_DIR = "dingrtc/cache/devices";
    private static final String DEVICES_FILE_NAME = ".DEVICES";
    private static final String DEVICES_ID_KEY = "DEVICES_ID_KEY";

    private DeviceUuid() {
    }

    public static String getDeviceID(Context context) {
        try {
            String readDeviceId = readDeviceID(context);
            SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
            String appDeviceId = preferences.getString(DEVICES_ID_KEY, "");
            if (!appDeviceId.isEmpty() && (readDeviceId == null || readDeviceId.isEmpty() || !appDeviceId.equals(readDeviceId))) {
                readDeviceId = appDeviceId;
                saveDeviceID(readDeviceId, context);
            }
            if (readDeviceId == null || readDeviceId.isEmpty()) {
                UUID uuid = UUID.randomUUID();
                readDeviceId = uuid.toString().replace("-", "");
                if (readDeviceId.length() > 0) {
                    saveDeviceID(readDeviceId, context);
                }
            }
            SharedPreferences.Editor editor = preferences.edit();
            editor.putString(DEVICES_ID_KEY, readDeviceId);
            editor.apply();
            return readDeviceId;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String readDeviceID(Context context) {
        if (Build.VERSION.SDK_INT >= 29) {
            return "";
        }
        File file = getDevicesDir(context);
        StringBuffer buffer = new StringBuffer();
        try {
            FileInputStream fis = new FileInputStream(file);
            InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
            Reader in = new BufferedReader(isr);
            while (true) {
                int i = in.read();
                if (i > -1) {
                    buffer.append((char) i);
                } else {
                    in.close();
                    return buffer.toString();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void saveDeviceID(String str, Context context) {
        if (Build.VERSION.SDK_INT >= 29) {
            return;
        }
        File file = getDevicesDir(context);
        try {
            FileOutputStream fos = new FileOutputStream(file);
            Writer out = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
            out.write(str);
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static File getDevicesDir(Context context) {
        File cropdir = new File(context.getFilesDir(), CACHE_IMAGE_DIR);
        if (!cropdir.exists()) {
            cropdir.mkdirs();
        }
        File cropFile = new File(cropdir, DEVICES_FILE_NAME);
        return cropFile;
    }
}

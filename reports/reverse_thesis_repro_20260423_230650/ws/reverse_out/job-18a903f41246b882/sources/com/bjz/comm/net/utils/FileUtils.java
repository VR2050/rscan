package com.bjz.comm.net.utils;

import java.io.File;
import java.io.IOException;

/* JADX INFO: loaded from: classes4.dex */
public class FileUtils {
    private static FileUtils mInstance;

    private FileUtils() {
    }

    public static FileUtils getInstance() {
        if (mInstance == null) {
            synchronized (FileUtils.class) {
                if (mInstance == null) {
                    mInstance = new FileUtils();
                }
            }
        }
        return mInstance;
    }

    public String getPicName(File file) throws IOException {
        String md5 = null;
        try {
            md5 = MD5Utils.getFileMD5String(file);
        } catch (IOException e) {
            e.printStackTrace();
        }
        String namePro = md5 + "_" + file.length() + "_1_1." + file.getName().substring(file.getName().lastIndexOf(".") + 1);
        return namePro;
    }
}

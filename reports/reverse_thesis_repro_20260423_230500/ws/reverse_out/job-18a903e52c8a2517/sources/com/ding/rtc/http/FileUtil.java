package com.ding.rtc.http;

import android.content.Context;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import java.util.Locale;

/* JADX INFO: loaded from: classes.dex */
public class FileUtil {
    private static final String TAG = "FileUtil";

    public enum SizeUnit {
        Byte,
        KB,
        MB,
        GB,
        TB,
        Auto
    }

    public static boolean hasExtension(String filename) {
        int dot = filename.lastIndexOf(46);
        return dot > -1 && dot < filename.length() - 1;
    }

    public static String getExtensionName(String filename) {
        int dot;
        if (filename != null && filename.length() > 0 && (dot = filename.lastIndexOf(46)) > -1 && dot < filename.length() - 1) {
            return filename.substring(dot + 1);
        }
        return "";
    }

    public static String getFileNameFromPath(String filepath) {
        int sep;
        if (filepath != null && filepath.length() > 0 && (sep = filepath.lastIndexOf(47)) > -1 && sep < filepath.length() - 1) {
            return filepath.substring(sep + 1);
        }
        return filepath;
    }

    public static String getFileNameNoEx(String filename) {
        int dot;
        if (filename != null && filename.length() > 0 && (dot = filename.lastIndexOf(46)) > -1 && dot < filename.length()) {
            return filename.substring(0, dot);
        }
        return filename;
    }

    public static String formatFileSize(long size) {
        return formatFileSize(size, SizeUnit.Auto);
    }

    public static String formatFileSize(long size, SizeUnit unit) {
        SizeUnit unit2;
        if (unit != SizeUnit.Auto) {
            unit2 = unit;
        } else if (size < 1024.0d) {
            unit2 = SizeUnit.Byte;
        } else if (size < 1048576.0d) {
            unit2 = SizeUnit.KB;
        } else if (size < 1.073741824E9d) {
            unit2 = SizeUnit.MB;
        } else if (size < 1.099511627776E12d) {
            unit2 = SizeUnit.GB;
        } else {
            unit2 = SizeUnit.TB;
        }
        int i = AnonymousClass1.$SwitchMap$com$ding$rtc$http$FileUtil$SizeUnit[unit2.ordinal()];
        if (i == 1) {
            return String.format(Locale.US, "%.2fKB", Double.valueOf(size / 1024.0d));
        }
        if (i == 2) {
            return String.format(Locale.US, "%.2fMB", Double.valueOf(size / 1048576.0d));
        }
        if (i == 3) {
            return String.format(Locale.US, "%.2fGB", Double.valueOf(size / 1.073741824E9d));
        }
        if (i == 4) {
            return String.format(Locale.US, "%.2fPB", Double.valueOf(size / 1.099511627776E12d));
        }
        return size + "B";
    }

    /* JADX INFO: renamed from: com.ding.rtc.http.FileUtil$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$ding$rtc$http$FileUtil$SizeUnit;

        static {
            int[] iArr = new int[SizeUnit.values().length];
            $SwitchMap$com$ding$rtc$http$FileUtil$SizeUnit = iArr;
            try {
                iArr[SizeUnit.KB.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$ding$rtc$http$FileUtil$SizeUnit[SizeUnit.MB.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$ding$rtc$http$FileUtil$SizeUnit[SizeUnit.GB.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$com$ding$rtc$http$FileUtil$SizeUnit[SizeUnit.TB.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
        }
    }

    public static boolean createFilePath(File file, String filePath) {
        File fPath;
        int index = filePath.indexOf("/");
        if (index == -1) {
            return false;
        }
        if (index == 0) {
            filePath = filePath.substring(index + 1);
            index = filePath.indexOf("/");
        }
        String path = filePath.substring(0, index);
        if (file != null) {
            fPath = new File(file.getPath() + "/" + path);
        } else {
            fPath = new File(path);
        }
        if (!fPath.exists() && !fPath.mkdir()) {
            return false;
        }
        if (index < filePath.length() - 1) {
            String exPath = filePath.substring(index + 1);
            createFilePath(fPath, exPath);
        }
        return true;
    }

    public static String getContentFileFDForNative(Context context, String urlString) {
        if (TextUtils.isEmpty(urlString) || context == null) {
            return urlString;
        }
        Uri uri = Uri.parse(urlString);
        if (TextUtils.equals(uri.getScheme(), "file")) {
            return new File(uri.getPath()).getAbsolutePath();
        }
        if (!TextUtils.equals(uri.getScheme(), "content")) {
            return urlString;
        }
        try {
            ParcelFileDescriptor fileDescriptor = context.getContentResolver().openFileDescriptor(uri, "r");
            return "/android_content_fd/" + fileDescriptor.detachFd();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return urlString;
        }
    }

    public static void closeQuietly(Closeable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (IOException e) {
        }
    }

    public static void deleteFiles(List<String> filePaths) {
        if (filePaths == null || filePaths.isEmpty()) {
            return;
        }
        for (String next : filePaths) {
            deleteFile(new File(next));
        }
    }

    public static void deleteFile(File file) {
        if (!file.exists()) {
            return;
        }
        if (file.isFile()) {
            file.delete();
            return;
        }
        String[] fileList = file.list();
        if (fileList == null || fileList.length == 0) {
            file.delete();
            return;
        }
        for (String name : fileList) {
            deleteFile(new File(file, name));
        }
    }
}

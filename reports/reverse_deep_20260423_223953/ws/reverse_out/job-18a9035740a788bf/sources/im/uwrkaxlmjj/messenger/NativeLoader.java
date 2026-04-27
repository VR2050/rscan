package im.uwrkaxlmjj.messenger;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/* JADX INFO: loaded from: classes2.dex */
public class NativeLoader {
    private static final String LIB_NAME = "tmessages.31";
    private static final String LIB_SO_NAME = "libtmessages.31.so";
    private static final int LIB_VERSION = 31;
    private static final String LOCALE_LIB_SO_NAME = "libtmessages.31loc.so";
    private static volatile boolean nativeLoaded = false;
    private String crashPath = "";

    private static native void init(String str, boolean z);

    private static File getNativeLibraryDir(Context context) {
        File f = null;
        if (context != null) {
            try {
                f = new File((String) ApplicationInfo.class.getField("nativeLibraryDir").get(context.getApplicationInfo()));
            } catch (Throwable th) {
                th.printStackTrace();
            }
        }
        if (f == null) {
            f = new File(context.getApplicationInfo().dataDir, "lib");
        }
        if (f.isDirectory()) {
            return f;
        }
        return null;
    }

    private static boolean loadFromZip(Context context, File destDir, File destLocalFile, String folder) {
        try {
            for (File file : destDir.listFiles()) {
                file.delete();
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        ZipFile zipFile = null;
        InputStream stream = null;
        try {
            try {
                ZipFile zipFile2 = new ZipFile(context.getApplicationInfo().sourceDir);
                ZipEntry entry = zipFile2.getEntry("lib/" + folder + "/" + LIB_SO_NAME);
                if (entry == null) {
                    throw new Exception("Unable to find file in apk:lib/" + folder + "/" + LIB_NAME);
                }
                InputStream stream2 = zipFile2.getInputStream(entry);
                OutputStream out = new FileOutputStream(destLocalFile);
                byte[] buf = new byte[4096];
                while (true) {
                    int len = stream2.read(buf);
                    if (len <= 0) {
                        break;
                    }
                    Thread.yield();
                    out.write(buf, 0, len);
                }
                out.close();
                destLocalFile.setReadable(true, false);
                destLocalFile.setExecutable(true, false);
                destLocalFile.setWritable(true);
                try {
                    System.load(destLocalFile.getAbsolutePath());
                    nativeLoaded = true;
                } catch (Error e2) {
                    FileLog.e(e2);
                }
                if (stream2 != null) {
                    try {
                        stream2.close();
                    } catch (Exception e3) {
                        FileLog.e(e3);
                    }
                }
                try {
                    zipFile2.close();
                } catch (Exception e4) {
                    FileLog.e(e4);
                }
                return true;
            } finally {
            }
        } catch (Exception e5) {
            FileLog.e(e5);
            if (0 != 0) {
                try {
                    stream.close();
                } catch (Exception e6) {
                    FileLog.e(e6);
                }
            }
            if (0 != 0) {
                try {
                    zipFile.close();
                } catch (Exception e7) {
                    FileLog.e(e7);
                }
            }
            return false;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:59:0x00e3 A[Catch: all -> 0x001c, TryCatch #5 {all -> 0x001c, blocks: (B:9:0x000a, B:11:0x0015, B:17:0x0020, B:18:0x0023, B:42:0x0096, B:44:0x009e, B:47:0x00a9, B:49:0x00c4, B:51:0x00c8, B:52:0x00cd, B:57:0x00df, B:59:0x00e3, B:60:0x00f7, B:56:0x00d9, B:21:0x0032, B:24:0x003f, B:27:0x004c, B:30:0x0059, B:33:0x0066, B:36:0x0073, B:38:0x0079, B:41:0x0091), top: B:78:0x000a, outer: #1, inners: #0, #2, #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00fe A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static synchronized void initNativeLibs(android.content.Context r8) {
        /*
            Method dump skipped, instruction units count: 276
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.NativeLoader.initNativeLibs(android.content.Context):void");
    }
}

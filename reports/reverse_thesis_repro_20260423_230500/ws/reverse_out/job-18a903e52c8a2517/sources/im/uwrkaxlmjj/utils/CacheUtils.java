package im.uwrkaxlmjj.utils;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.os.Process;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.json.JSONArray;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes5.dex */
public class CacheUtils {
    private static final int MAX_COUNT = Integer.MAX_VALUE;
    private static final int MAX_SIZE = 50000000;
    public static final int TIME_DAY = 86400;
    public static final int TIME_HOUR = 3600;
    private static Map<String, CacheUtils> mInstanceMap = new HashMap();
    private ACacheManager mCache;

    public static CacheUtils get(Context ctx) {
        return get(ctx, "ACache");
    }

    public static CacheUtils get(Context ctx, String cacheName) {
        File f = new File(ctx.getCacheDir(), cacheName);
        return get(f, 50000000L, Integer.MAX_VALUE);
    }

    public static CacheUtils get(File cacheDir) {
        return get(cacheDir, 50000000L, Integer.MAX_VALUE);
    }

    public static CacheUtils get(Context ctx, long max_zise, int max_count) {
        File f = new File(ctx.getCacheDir(), "ACache");
        return get(f, max_zise, max_count);
    }

    public static CacheUtils get(File cacheDir, long max_zise, int max_count) {
        CacheUtils manager = mInstanceMap.get(cacheDir.getAbsoluteFile() + myPid());
        if (manager == null) {
            CacheUtils manager2 = new CacheUtils(cacheDir, max_zise, max_count);
            mInstanceMap.put(cacheDir.getAbsolutePath() + myPid(), manager2);
            return manager2;
        }
        return manager;
    }

    private static String myPid() {
        return "_" + Process.myPid();
    }

    private CacheUtils(File cacheDir, long max_size, int max_count) {
        if (!cacheDir.exists() && !cacheDir.mkdirs()) {
            throw new RuntimeException("can't make dirs in " + cacheDir.getAbsolutePath());
        }
        this.mCache = new ACacheManager(cacheDir, max_size, max_count);
    }

    class xFileOutputStream extends FileOutputStream {
        File file;

        public xFileOutputStream(File file) throws FileNotFoundException {
            super(file);
            this.file = file;
        }

        @Override // java.io.FileOutputStream, java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            super.close();
            CacheUtils.this.mCache.put(this.file);
        }
    }

    public void put(String key, String value) {
        File file = this.mCache.newFile(key);
        BufferedWriter out = null;
        try {
            try {
                out = new BufferedWriter(new FileWriter(file), 1024);
                out.write(value);
            } catch (IOException e) {
                e.printStackTrace();
                if (out != null) {
                    try {
                        out.flush();
                        out.close();
                    } catch (IOException e2) {
                        e = e2;
                        e.printStackTrace();
                    }
                }
            }
            try {
                out.flush();
                out.close();
            } catch (IOException e3) {
                e = e3;
                e.printStackTrace();
            }
            this.mCache.put(file);
        } catch (Throwable th) {
            if (out != null) {
                try {
                    out.flush();
                    out.close();
                } catch (IOException e4) {
                    e4.printStackTrace();
                }
            }
            this.mCache.put(file);
            throw th;
        }
    }

    public void put(String key, String value, int saveTime) {
        put(key, Utils.newStringWithDateInfo(saveTime, value));
    }

    /* JADX WARN: Removed duplicated region for block: B:46:0x0082 A[DONT_GENERATE, FINALLY_INSNS] */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0078 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:60:? A[DONT_GENERATE, FINALLY_INSNS, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.String getAsString(java.lang.String r8) {
        /*
            r7 = this;
            im.uwrkaxlmjj.utils.CacheUtils$ACacheManager r0 = r7.mCache
            java.io.File r0 = im.uwrkaxlmjj.utils.CacheUtils.ACacheManager.access$500(r0, r8)
            boolean r1 = r0.exists()
            r2 = 0
            if (r1 != 0) goto Le
            return r2
        Le:
            r1 = 0
            r3 = 0
            java.io.BufferedReader r4 = new java.io.BufferedReader     // Catch: java.lang.Throwable -> L5f java.io.IOException -> L61
            java.io.FileReader r5 = new java.io.FileReader     // Catch: java.lang.Throwable -> L5f java.io.IOException -> L61
            r5.<init>(r0)     // Catch: java.lang.Throwable -> L5f java.io.IOException -> L61
            r4.<init>(r5)     // Catch: java.lang.Throwable -> L5f java.io.IOException -> L61
            r3 = r4
            java.lang.String r4 = ""
        L1d:
            java.lang.String r5 = r3.readLine()     // Catch: java.lang.Throwable -> L5f java.io.IOException -> L61
            r6 = r5
            if (r5 == 0) goto L35
            java.lang.StringBuilder r5 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L5f java.io.IOException -> L61
            r5.<init>()     // Catch: java.lang.Throwable -> L5f java.io.IOException -> L61
            r5.append(r4)     // Catch: java.lang.Throwable -> L5f java.io.IOException -> L61
            r5.append(r6)     // Catch: java.lang.Throwable -> L5f java.io.IOException -> L61
            java.lang.String r5 = r5.toString()     // Catch: java.lang.Throwable -> L5f java.io.IOException -> L61
            r4 = r5
            goto L1d
        L35:
            boolean r5 = im.uwrkaxlmjj.utils.CacheUtils.Utils.access$600(r4)     // Catch: java.lang.Throwable -> L5f java.io.IOException -> L61
            if (r5 != 0) goto L4e
            java.lang.String r2 = im.uwrkaxlmjj.utils.CacheUtils.Utils.access$700(r4)     // Catch: java.lang.Throwable -> L5f java.io.IOException -> L61
            r3.close()     // Catch: java.io.IOException -> L44
            goto L48
        L44:
            r5 = move-exception
            r5.printStackTrace()
        L48:
            if (r1 == 0) goto L4d
            r7.remove(r8)
        L4d:
            return r2
        L4e:
            r1 = 1
            r3.close()     // Catch: java.io.IOException -> L55
            goto L59
        L55:
            r5 = move-exception
            r5.printStackTrace()
        L59:
            if (r1 == 0) goto L5e
            r7.remove(r8)
        L5e:
            return r2
        L5f:
            r2 = move-exception
            goto L76
        L61:
            r4 = move-exception
            r4.printStackTrace()     // Catch: java.lang.Throwable -> L5f
            if (r3 == 0) goto L70
            r3.close()     // Catch: java.io.IOException -> L6c
            goto L70
        L6c:
            r5 = move-exception
            r5.printStackTrace()
        L70:
            if (r1 == 0) goto L75
            r7.remove(r8)
        L75:
            return r2
        L76:
            if (r3 == 0) goto L80
            r3.close()     // Catch: java.io.IOException -> L7c
            goto L80
        L7c:
            r4 = move-exception
            r4.printStackTrace()
        L80:
            if (r1 == 0) goto L85
            r7.remove(r8)
        L85:
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.utils.CacheUtils.getAsString(java.lang.String):java.lang.String");
    }

    public void put(String key, JSONObject value) {
        put(key, value.toString());
    }

    public void put(String key, JSONObject value, int saveTime) {
        put(key, value.toString(), saveTime);
    }

    public JSONObject getAsJSONObject(String key) {
        String JSONString = getAsString(key);
        try {
            JSONObject obj = new JSONObject(JSONString);
            return obj;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void put(String key, JSONArray value) {
        put(key, value.toString());
    }

    public void put(String key, JSONArray value, int saveTime) {
        put(key, value.toString(), saveTime);
    }

    public JSONArray getAsJSONArray(String key) {
        String JSONString = getAsString(key);
        try {
            JSONArray obj = new JSONArray(JSONString);
            return obj;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void put(String key, byte[] value) {
        File file = this.mCache.newFile(key);
        FileOutputStream out = null;
        try {
            try {
                out = new FileOutputStream(file);
                out.write(value);
                try {
                    out.flush();
                    out.close();
                } catch (IOException e) {
                    e = e;
                    e.printStackTrace();
                }
            } catch (Exception e2) {
                e2.printStackTrace();
                if (out != null) {
                    try {
                        out.flush();
                        out.close();
                    } catch (IOException e3) {
                        e = e3;
                        e.printStackTrace();
                    }
                }
            }
            this.mCache.put(file);
        } catch (Throwable th) {
            if (out != null) {
                try {
                    out.flush();
                    out.close();
                } catch (IOException e4) {
                    e4.printStackTrace();
                }
            }
            this.mCache.put(file);
            throw th;
        }
    }

    public OutputStream put(String key) throws FileNotFoundException {
        return new xFileOutputStream(this.mCache.newFile(key));
    }

    public InputStream get(String key) throws FileNotFoundException {
        File file = this.mCache.get(key);
        if (!file.exists()) {
            return null;
        }
        return new FileInputStream(file);
    }

    public void put(String key, byte[] value, int saveTime) {
        put(key, Utils.newByteArrayWithDateInfo(saveTime, value));
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x007f A[DONT_GENERATE, FINALLY_INSNS] */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0075 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:64:? A[DONT_GENERATE, FINALLY_INSNS, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public byte[] getAsBinary(java.lang.String r7) {
        /*
            r6 = this;
            r0 = 0
            r1 = 0
            r2 = 0
            im.uwrkaxlmjj.utils.CacheUtils$ACacheManager r3 = r6.mCache     // Catch: java.lang.Throwable -> L5c java.lang.Exception -> L5e
            java.io.File r3 = im.uwrkaxlmjj.utils.CacheUtils.ACacheManager.access$500(r3, r7)     // Catch: java.lang.Throwable -> L5c java.lang.Exception -> L5e
            boolean r4 = r3.exists()     // Catch: java.lang.Throwable -> L5c java.lang.Exception -> L5e
            if (r4 != 0) goto L20
        L10:
            if (r0 == 0) goto L1a
            r0.close()     // Catch: java.io.IOException -> L16
            goto L1a
        L16:
            r4 = move-exception
            r4.printStackTrace()
        L1a:
            if (r1 == 0) goto L1f
            r6.remove(r7)
        L1f:
            return r2
        L20:
            java.io.RandomAccessFile r4 = new java.io.RandomAccessFile     // Catch: java.lang.Throwable -> L5c java.lang.Exception -> L5e
            java.lang.String r5 = "r"
            r4.<init>(r3, r5)     // Catch: java.lang.Throwable -> L5c java.lang.Exception -> L5e
            r0 = r4
            long r4 = r0.length()     // Catch: java.lang.Throwable -> L5c java.lang.Exception -> L5e
            int r5 = (int) r4     // Catch: java.lang.Throwable -> L5c java.lang.Exception -> L5e
            byte[] r4 = new byte[r5]     // Catch: java.lang.Throwable -> L5c java.lang.Exception -> L5e
            r0.read(r4)     // Catch: java.lang.Throwable -> L5c java.lang.Exception -> L5e
            boolean r5 = im.uwrkaxlmjj.utils.CacheUtils.Utils.access$900(r4)     // Catch: java.lang.Throwable -> L5c java.lang.Exception -> L5e
            if (r5 != 0) goto L4b
            byte[] r2 = im.uwrkaxlmjj.utils.CacheUtils.Utils.access$1000(r4)     // Catch: java.lang.Throwable -> L5c java.lang.Exception -> L5e
            r0.close()     // Catch: java.io.IOException -> L41
            goto L45
        L41:
            r5 = move-exception
            r5.printStackTrace()
        L45:
            if (r1 == 0) goto L4a
            r6.remove(r7)
        L4a:
            return r2
        L4b:
            r1 = 1
            r0.close()     // Catch: java.io.IOException -> L52
            goto L56
        L52:
            r5 = move-exception
            r5.printStackTrace()
        L56:
            if (r1 == 0) goto L5b
            r6.remove(r7)
        L5b:
            return r2
        L5c:
            r2 = move-exception
            goto L73
        L5e:
            r3 = move-exception
            r3.printStackTrace()     // Catch: java.lang.Throwable -> L5c
            if (r0 == 0) goto L6d
            r0.close()     // Catch: java.io.IOException -> L69
            goto L6d
        L69:
            r4 = move-exception
            r4.printStackTrace()
        L6d:
            if (r1 == 0) goto L72
            r6.remove(r7)
        L72:
            return r2
        L73:
            if (r0 == 0) goto L7d
            r0.close()     // Catch: java.io.IOException -> L79
            goto L7d
        L79:
            r3 = move-exception
            r3.printStackTrace()
        L7d:
            if (r1 == 0) goto L82
            r6.remove(r7)
        L82:
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.utils.CacheUtils.getAsBinary(java.lang.String):byte[]");
    }

    public void put(String key, Serializable value) {
        put(key, value, -1);
    }

    public void put(String key, Serializable value, int saveTime) {
        ObjectOutputStream oos = null;
        try {
            try {
                try {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ObjectOutputStream oos2 = new ObjectOutputStream(baos);
                    oos2.writeObject(value);
                    byte[] data = baos.toByteArray();
                    if (saveTime != -1) {
                        put(key, data, saveTime);
                    } else {
                        put(key, data);
                    }
                    oos2.close();
                } catch (Throwable th) {
                    try {
                        oos.close();
                    } catch (IOException e) {
                    }
                    throw th;
                }
            } catch (Exception e2) {
                e2.printStackTrace();
                oos.close();
            }
        } catch (IOException e3) {
        }
    }

    public Object getAsObject(String key) {
        byte[] data = getAsBinary(key);
        if (data == null) {
            return null;
        }
        ByteArrayInputStream bais = null;
        ObjectInputStream ois = null;
        try {
            try {
                bais = new ByteArrayInputStream(data);
                ois = new ObjectInputStream(bais);
                Object reObject = ois.readObject();
                try {
                    bais.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                try {
                    ois.close();
                } catch (IOException e2) {
                    e2.printStackTrace();
                }
                return reObject;
            } catch (Exception e3) {
                e3.printStackTrace();
                if (bais != null) {
                    try {
                        bais.close();
                    } catch (IOException e4) {
                        e4.printStackTrace();
                    }
                }
                if (ois != null) {
                    try {
                        ois.close();
                    } catch (IOException e5) {
                        e5.printStackTrace();
                    }
                }
                return null;
            }
        } finally {
        }
    }

    public void put(String key, Bitmap value) {
        put(key, Utils.Bitmap2Bytes(value));
    }

    public void put(String key, Bitmap value, int saveTime) {
        put(key, Utils.Bitmap2Bytes(value), saveTime);
    }

    public Bitmap getAsBitmap(String key) {
        if (getAsBinary(key) == null) {
            return null;
        }
        return Utils.Bytes2Bimap(getAsBinary(key));
    }

    public void put(String key, Drawable value) {
        put(key, Utils.drawable2Bitmap(value));
    }

    public void put(String key, Drawable value, int saveTime) {
        put(key, Utils.drawable2Bitmap(value), saveTime);
    }

    public Drawable getAsDrawable(String key) {
        if (getAsBinary(key) == null) {
            return null;
        }
        return Utils.bitmap2Drawable(Utils.Bytes2Bimap(getAsBinary(key)));
    }

    public File file(String key) {
        File f = this.mCache.newFile(key);
        if (f.exists()) {
            return f;
        }
        return null;
    }

    public boolean remove(String key) {
        return this.mCache.remove(key);
    }

    public void clear() {
        this.mCache.clear();
    }

    public class ACacheManager {
        private final AtomicInteger cacheCount;
        protected File cacheDir;
        private final AtomicLong cacheSize;
        private final int countLimit;
        private final Map<File, Long> lastUsageDates;
        private final long sizeLimit;

        private ACacheManager(File cacheDir, long sizeLimit, int countLimit) {
            this.lastUsageDates = Collections.synchronizedMap(new HashMap());
            this.cacheDir = cacheDir;
            this.sizeLimit = sizeLimit;
            this.countLimit = countLimit;
            this.cacheSize = new AtomicLong();
            this.cacheCount = new AtomicInteger();
            calculateCacheSizeAndCacheCount();
        }

        private void calculateCacheSizeAndCacheCount() {
            new Thread(new Runnable() { // from class: im.uwrkaxlmjj.utils.CacheUtils.ACacheManager.1
                @Override // java.lang.Runnable
                public void run() {
                    int size = 0;
                    int count = 0;
                    File[] cachedFiles = ACacheManager.this.cacheDir.listFiles();
                    if (cachedFiles != null) {
                        for (File cachedFile : cachedFiles) {
                            size = (int) (((long) size) + ACacheManager.this.calculateSize(cachedFile));
                            count++;
                            ACacheManager.this.lastUsageDates.put(cachedFile, Long.valueOf(cachedFile.lastModified()));
                        }
                        ACacheManager.this.cacheSize.set(size);
                        ACacheManager.this.cacheCount.set(count);
                    }
                }
            }).start();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void put(File file) {
            int curCacheCount = this.cacheCount.get();
            while (curCacheCount + 1 > this.countLimit) {
                long freedSize = removeNext();
                this.cacheSize.addAndGet(-freedSize);
                curCacheCount = this.cacheCount.addAndGet(-1);
            }
            this.cacheCount.addAndGet(1);
            long valueSize = calculateSize(file);
            long curCacheSize = this.cacheSize.get();
            while (curCacheSize + valueSize > this.sizeLimit) {
                long freedSize2 = removeNext();
                curCacheSize = this.cacheSize.addAndGet(-freedSize2);
            }
            this.cacheSize.addAndGet(valueSize);
            Long currentTime = Long.valueOf(System.currentTimeMillis());
            file.setLastModified(currentTime.longValue());
            this.lastUsageDates.put(file, currentTime);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public File get(String key) {
            File file = newFile(key);
            Long currentTime = Long.valueOf(System.currentTimeMillis());
            file.setLastModified(currentTime.longValue());
            this.lastUsageDates.put(file, currentTime);
            return file;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public File newFile(String key) {
            return new File(this.cacheDir, key.hashCode() + "");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public boolean remove(String key) {
            File image = get(key);
            return image.delete();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clear() {
            this.lastUsageDates.clear();
            this.cacheSize.set(0L);
            File[] files = this.cacheDir.listFiles();
            if (files != null) {
                for (File f : files) {
                    f.delete();
                }
            }
        }

        private long removeNext() {
            if (this.lastUsageDates.isEmpty()) {
                return 0L;
            }
            Long oldestUsage = null;
            File mostLongUsedFile = null;
            Set<Map.Entry<File, Long>> entries = this.lastUsageDates.entrySet();
            synchronized (this.lastUsageDates) {
                for (Map.Entry<File, Long> entry : entries) {
                    if (mostLongUsedFile == null) {
                        mostLongUsedFile = entry.getKey();
                        oldestUsage = entry.getValue();
                    } else {
                        Long lastValueUsage = entry.getValue();
                        if (lastValueUsage.longValue() < oldestUsage.longValue()) {
                            oldestUsage = lastValueUsage;
                            mostLongUsedFile = entry.getKey();
                        }
                    }
                }
            }
            long fileSize = calculateSize(mostLongUsedFile);
            if (mostLongUsedFile.delete()) {
                this.lastUsageDates.remove(mostLongUsedFile);
            }
            return fileSize;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public long calculateSize(File file) {
            return file.length();
        }
    }

    private static class Utils {
        private static final char mSeparator = ' ';

        private Utils() {
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static boolean isDue(String str) {
            return isDue(str.getBytes());
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static boolean isDue(byte[] data) {
            String[] strs = getDateInfoFromDate(data);
            if (strs != null && strs.length == 2) {
                String saveTimeStr = strs[0];
                while (saveTimeStr.startsWith("0")) {
                    saveTimeStr = saveTimeStr.substring(1, saveTimeStr.length());
                }
                long saveTime = Long.valueOf(saveTimeStr).longValue();
                long deleteAfter = Long.valueOf(strs[1]).longValue();
                if (System.currentTimeMillis() > (1000 * deleteAfter) + saveTime) {
                    return true;
                }
            }
            return false;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static String newStringWithDateInfo(int second, String strInfo) {
            return createDateInfo(second) + strInfo;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static byte[] newByteArrayWithDateInfo(int second, byte[] data2) {
            byte[] data1 = createDateInfo(second).getBytes();
            byte[] retdata = new byte[data1.length + data2.length];
            System.arraycopy(data1, 0, retdata, 0, data1.length);
            System.arraycopy(data2, 0, retdata, data1.length, data2.length);
            return retdata;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static String clearDateInfo(String strInfo) {
            if (strInfo != null && hasDateInfo(strInfo.getBytes())) {
                return strInfo.substring(strInfo.indexOf(32) + 1, strInfo.length());
            }
            return strInfo;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static byte[] clearDateInfo(byte[] data) {
            if (hasDateInfo(data)) {
                return copyOfRange(data, indexOf(data, mSeparator) + 1, data.length);
            }
            return data;
        }

        private static boolean hasDateInfo(byte[] data) {
            return data != null && data.length > 15 && data[13] == 45 && indexOf(data, mSeparator) > 14;
        }

        private static String[] getDateInfoFromDate(byte[] data) {
            if (hasDateInfo(data)) {
                String saveDate = new String(copyOfRange(data, 0, 13));
                String deleteAfter = new String(copyOfRange(data, 14, indexOf(data, mSeparator)));
                return new String[]{saveDate, deleteAfter};
            }
            return null;
        }

        private static int indexOf(byte[] data, char c) {
            for (int i = 0; i < data.length; i++) {
                if (data[i] == c) {
                    return i;
                }
            }
            return -1;
        }

        private static byte[] copyOfRange(byte[] original, int from, int to) {
            int newLength = to - from;
            if (newLength < 0) {
                throw new IllegalArgumentException(from + " > " + to);
            }
            byte[] copy = new byte[newLength];
            System.arraycopy(original, from, copy, 0, Math.min(original.length - from, newLength));
            return copy;
        }

        private static String createDateInfo(int second) {
            String currentTime = System.currentTimeMillis() + "";
            while (currentTime.length() < 13) {
                currentTime = "0" + currentTime;
            }
            return currentTime + "-" + second + mSeparator;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static byte[] Bitmap2Bytes(Bitmap bm) {
            if (bm == null) {
                return null;
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            bm.compress(Bitmap.CompressFormat.PNG, 100, baos);
            return baos.toByteArray();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static Bitmap Bytes2Bimap(byte[] b) {
            if (b.length == 0) {
                return null;
            }
            return BitmapFactory.decodeByteArray(b, 0, b.length);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static Bitmap drawable2Bitmap(Drawable drawable) {
            if (drawable == null) {
                return null;
            }
            int w = drawable.getIntrinsicWidth();
            int h = drawable.getIntrinsicHeight();
            Bitmap.Config config = drawable.getOpacity() != -1 ? Bitmap.Config.ARGB_8888 : Bitmap.Config.RGB_565;
            Bitmap bitmap = Bitmap.createBitmap(w, h, config);
            Canvas canvas = new Canvas(bitmap);
            drawable.setBounds(0, 0, w, h);
            drawable.draw(canvas);
            return bitmap;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static Drawable bitmap2Drawable(Bitmap bm) {
            if (bm == null) {
                return null;
            }
            BitmapDrawable bd = new BitmapDrawable(bm);
            bd.setTargetDensity(bm.getDensity());
            return new BitmapDrawable(bm);
        }
    }
}

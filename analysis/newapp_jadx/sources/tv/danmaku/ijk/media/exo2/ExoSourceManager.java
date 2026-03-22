package tv.danmaku.ijk.media.exo2;

import android.annotation.SuppressLint;
import android.content.Context;
import android.net.Uri;
import android.text.TextUtils;
import androidx.annotation.Nullable;
import java.io.File;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.NavigableSet;
import p005b.p199l.p200a.p201a.p248o1.C2326r;
import p005b.p199l.p200a.p201a.p248o1.C2328t;
import p005b.p199l.p200a.p201a.p248o1.C2330v;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p248o1.p249h0.C2301g;
import p005b.p199l.p200a.p201a.p248o1.p249h0.C2305k;
import p005b.p199l.p200a.p201a.p248o1.p249h0.C2306l;
import p005b.p199l.p200a.p201a.p248o1.p249h0.C2312r;
import p005b.p199l.p200a.p201a.p248o1.p249h0.C2313s;
import p005b.p199l.p200a.p201a.p248o1.p249h0.C2315u;
import p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import tv.danmaku.ijk.media.exo2.source.GSYExoHttpDataSourceFactory;

/* loaded from: classes3.dex */
public class ExoSourceManager {
    private static final long DEFAULT_MAX_SIZE = 536870912;
    private static final String TAG = "ExoSourceManager";
    public static final int TYPE_RTMP = 4;
    private static InterfaceC2297c mCache = null;

    /* renamed from: s */
    private static boolean f13000s = false;
    private static ExoMediaSourceInterceptListener sExoMediaSourceInterceptListener = null;
    private static int sHttpConnectTimeout = -1;
    private static int sHttpReadTimeout = -1;
    private static boolean sSkipSSLChain = false;
    private boolean isCached = false;
    private Context mAppContext;
    private String mDataSource;
    private Map<String, String> mMapHeadData;

    private ExoSourceManager(Context context, Map<String, String> map) {
        this.mAppContext = context.getApplicationContext();
        this.mMapHeadData = map;
    }

    public static boolean cachePreView(Context context, File file, String str) {
        return resolveCacheState(getCacheSingleInstance(context, file), str);
    }

    public static void clearCache(Context context, File file, String str) {
        try {
            InterfaceC2297c cacheSingleInstance = getCacheSingleInstance(context, file);
            if (TextUtils.isEmpty(str)) {
                if (cacheSingleInstance != null) {
                    Iterator<String> it = cacheSingleInstance.mo2205f().iterator();
                    while (it.hasNext()) {
                        C2306l.m2226a(cacheSingleInstance, it.next());
                    }
                    return;
                }
                return;
            }
            if (cacheSingleInstance != null) {
                Uri parse = Uri.parse(str);
                int i2 = C2306l.f5869a;
                C2306l.m2226a(cacheSingleInstance, parse.toString());
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public static synchronized InterfaceC2297c getCacheSingleInstance(Context context, File file) {
        InterfaceC2297c interfaceC2297c;
        boolean contains;
        synchronized (ExoSourceManager.class) {
            String absolutePath = context.getCacheDir().getAbsolutePath();
            if (file != null) {
                absolutePath = file.getAbsolutePath();
            }
            if (mCache == null) {
                String str = absolutePath + File.separator + "exo";
                File file2 = new File(str);
                HashSet<File> hashSet = C2315u.f5902a;
                synchronized (C2315u.class) {
                    contains = C2315u.f5902a.contains(file2.getAbsoluteFile());
                }
                if (!contains) {
                    mCache = new C2315u(new File(str), new C2313s(536870912L));
                }
            }
            interfaceC2297c = mCache;
        }
        return interfaceC2297c;
    }

    private InterfaceC2321m.a getDataSourceFactory(Context context, boolean z) {
        return new C2328t(context, z ? null : new C2326r.a(context).m2275a(), getHttpDataSourceFactory(context, z));
    }

    private InterfaceC2321m.a getDataSourceFactoryCache(Context context, boolean z, boolean z2, File file) {
        InterfaceC2297c cacheSingleInstance;
        if (!z || (cacheSingleInstance = getCacheSingleInstance(context, file)) == null) {
            return getDataSourceFactory(context, z2);
        }
        this.isCached = resolveCacheState(cacheSingleInstance, this.mDataSource);
        return new C2301g(cacheSingleInstance, getDataSourceFactory(context, z2), 2);
    }

    public static ExoMediaSourceInterceptListener getExoMediaSourceInterceptListener() {
        return sExoMediaSourceInterceptListener;
    }

    public static int getHttpConnectTimeout() {
        return sHttpConnectTimeout;
    }

    private InterfaceC2321m.a getHttpDataSourceFactory(Context context, boolean z) {
        int i2 = sHttpConnectTimeout;
        int i3 = i2 > 0 ? i2 : 8000;
        int i4 = sHttpReadTimeout;
        int i5 = i4 > 0 ? i4 : 8000;
        Map<String, String> map = this.mMapHeadData;
        boolean equals = (map == null || map.size() <= 0) ? false : "true".equals(this.mMapHeadData.get("allowCrossProtocolRedirects"));
        if (sSkipSSLChain) {
            GSYExoHttpDataSourceFactory gSYExoHttpDataSourceFactory = new GSYExoHttpDataSourceFactory(C2344d0.m2341s(context, TAG), z ? null : new C2326r.a(this.mAppContext).m2275a(), i3, i5, equals);
            Map<String, String> map2 = this.mMapHeadData;
            if (map2 != null && map2.size() > 0) {
                for (Map.Entry<String, String> entry : this.mMapHeadData.entrySet()) {
                    gSYExoHttpDataSourceFactory.getDefaultRequestProperties().m2284b(entry.getKey(), entry.getValue());
                }
            }
            return gSYExoHttpDataSourceFactory;
        }
        C2330v c2330v = new C2330v(C2344d0.m2341s(context, TAG), z ? null : new C2326r.a(this.mAppContext).m2275a(), i3, i5, equals);
        Map<String, String> map3 = this.mMapHeadData;
        if (map3 != null && map3.size() > 0) {
            for (Map.Entry<String, String> entry2 : this.mMapHeadData.entrySet()) {
                c2330v.getDefaultRequestProperties().m2284b(entry2.getKey(), entry2.getValue());
            }
        }
        return c2330v;
    }

    public static int getHttpReadTimeout() {
        return sHttpReadTimeout;
    }

    public static int inferContentType(Uri uri, @Nullable String str) {
        int i2 = C2344d0.f6035a;
        if (TextUtils.isEmpty(str)) {
            String path = uri.getPath();
            if (path == null) {
                return 3;
            }
            return C2344d0.m2343u(path);
        }
        return C2344d0.m2343u("." + str);
    }

    public static boolean isSkipSSLChain() {
        return sSkipSSLChain;
    }

    public static ExoSourceManager newInstance(Context context, @Nullable Map<String, String> map) {
        return new ExoSourceManager(context, map);
    }

    public static void resetExoMediaSourceInterceptListener() {
        sExoMediaSourceInterceptListener = null;
    }

    private static boolean resolveCacheState(InterfaceC2297c interfaceC2297c, String str) {
        if (TextUtils.isEmpty(str)) {
            return true;
        }
        Uri parse = Uri.parse(str);
        int i2 = C2306l.f5869a;
        String uri = parse.toString();
        if (!TextUtils.isEmpty(uri)) {
            NavigableSet<C2305k> mo2211l = interfaceC2297c.mo2211l(uri);
            if (mo2211l.size() != 0) {
                long m2252b = ((C2312r) interfaceC2297c.mo2201b(uri)).m2252b("exo_len", -1L);
                long j2 = 0;
                for (C2305k c2305k : mo2211l) {
                    j2 += interfaceC2297c.mo2204e(uri, c2305k.f5864e, c2305k.f5865f);
                }
                if (j2 >= m2252b) {
                    return true;
                }
            }
        }
        return false;
    }

    public static void setExoMediaSourceInterceptListener(ExoMediaSourceInterceptListener exoMediaSourceInterceptListener) {
        sExoMediaSourceInterceptListener = exoMediaSourceInterceptListener;
    }

    public static void setHttpConnectTimeout(int i2) {
        sHttpConnectTimeout = i2;
    }

    public static void setHttpReadTimeout(int i2) {
        sHttpReadTimeout = i2;
    }

    public static void setSkipSSLChain(boolean z) {
        sSkipSSLChain = z;
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x01a4  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x01aa A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y getMediaSource(java.lang.String r27, boolean r28, boolean r29, boolean r30, java.io.File r31, @androidx.annotation.Nullable java.lang.String r32) {
        /*
            Method dump skipped, instructions count: 427
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: tv.danmaku.ijk.media.exo2.ExoSourceManager.getMediaSource(java.lang.String, boolean, boolean, boolean, java.io.File, java.lang.String):b.l.a.a.k1.y");
    }

    public boolean hadCached() {
        return this.isCached;
    }

    public void release() {
        this.isCached = false;
        InterfaceC2297c interfaceC2297c = mCache;
        if (interfaceC2297c != null) {
            try {
                interfaceC2297c.release();
                mCache = null;
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    @SuppressLint({"WrongConstant"})
    public static int inferContentType(String str, @Nullable String str2) {
        String m2320L = C2344d0.m2320L(str);
        if (m2320L.startsWith("rtmp:")) {
            return 4;
        }
        return inferContentType(Uri.parse(m2320L), str2);
    }
}

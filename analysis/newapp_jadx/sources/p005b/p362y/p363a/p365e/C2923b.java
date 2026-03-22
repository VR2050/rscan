package p005b.p362y.p363a.p365e;

import android.content.Context;
import android.net.Uri;
import android.text.TextUtils;
import com.shuyu.gsyvideoplayer.utils.CommonUtil;
import com.shuyu.gsyvideoplayer.utils.FileUtils;
import com.shuyu.gsyvideoplayer.utils.StorageUtils;
import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p172h.p173a.C1817f;
import p005b.p172h.p173a.C1818g;
import p005b.p172h.p173a.C1825n;
import p005b.p172h.p173a.InterfaceC1813b;
import p005b.p172h.p173a.p174r.C1834f;
import p005b.p362y.p363a.AbstractC2919b;
import p005b.p362y.p363a.p365e.InterfaceC2922a;
import tv.danmaku.ijk.media.player.IMediaPlayer;

/* renamed from: b.y.a.e.b */
/* loaded from: classes2.dex */
public class C2923b implements InterfaceC2922a, InterfaceC1813b {

    /* renamed from: c */
    public static C2923b f8024c;

    /* renamed from: e */
    public C1818g f8025e;

    /* renamed from: f */
    public File f8026f;

    /* renamed from: g */
    public boolean f8027g;

    /* renamed from: h */
    public InterfaceC2922a.a f8028h;

    /* renamed from: i */
    public C2924c f8029i = new C2924c();

    /* JADX WARN: Removed duplicated region for block: B:16:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:18:0x006c  */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static p005b.p172h.p173a.C1818g m3398b(android.content.Context r9, java.io.File r10) {
        /*
            Method dump skipped, instructions count: 379
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p362y.p363a.p365e.C2923b.m3398b(android.content.Context, java.io.File):b.h.a.g");
    }

    /* renamed from: c */
    public static synchronized C2923b m3399c() {
        C2923b c2923b;
        synchronized (C2923b.class) {
            if (f8024c == null) {
                f8024c = new C2923b();
            }
            c2923b = f8024c;
        }
        return c2923b;
    }

    @Override // p005b.p172h.p173a.InterfaceC1813b
    /* renamed from: a */
    public void mo1159a(File file, String str, int i2) {
        InterfaceC2922a.a aVar = this.f8028h;
        if (aVar != null) {
            ((AbstractC2919b) aVar).f8004n = i2;
        }
    }

    @Override // p005b.p362y.p363a.p365e.InterfaceC2922a
    public boolean cachePreview(Context context, File file, String str) {
        return !m3398b(context.getApplicationContext(), file).m1168c(str).startsWith("http");
    }

    @Override // p005b.p362y.p363a.p365e.InterfaceC2922a
    public void clearCache(Context context, File file, String str) {
        if (TextUtils.isEmpty(str)) {
            FileUtils.deleteFiles(new File(StorageUtils.getIndividualCacheDirectory(context.getApplicationContext()).getAbsolutePath()));
            return;
        }
        String m1189a = new C1834f().m1189a(str);
        if (file != null) {
            StringBuilder sb = new StringBuilder();
            sb.append(file.getAbsolutePath());
            String str2 = File.separator;
            String m583E = C1499a.m583E(sb, str2, m1189a, ".download");
            String str3 = file.getAbsolutePath() + str2 + m1189a;
            CommonUtil.deleteFile(m583E);
            CommonUtil.deleteFile(str3);
            return;
        }
        StringBuilder sb2 = new StringBuilder();
        sb2.append(StorageUtils.getIndividualCacheDirectory(context.getApplicationContext()).getAbsolutePath());
        String str4 = File.separator;
        String m583E2 = C1499a.m583E(sb2, str4, m1189a, ".download");
        String str5 = StorageUtils.getIndividualCacheDirectory(context.getApplicationContext()).getAbsolutePath() + str4 + m1189a;
        CommonUtil.deleteFile(m583E2);
        CommonUtil.deleteFile(str5);
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0056  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x005c  */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public p005b.p172h.p173a.C1818g m3400d(android.content.Context r9, java.io.File r10) {
        /*
            r8 = this;
            boolean r0 = r10.exists()
            if (r0 != 0) goto L9
            r10.mkdirs()
        L9:
            b.h.a.t.a r5 = new b.h.a.t.a
            r5.<init>(r9)
            java.lang.String r0 = android.os.Environment.getExternalStorageState()     // Catch: java.lang.NullPointerException -> L13
            goto L15
        L13:
            java.lang.String r0 = ""
        L15:
            java.lang.String r1 = "HttpProxyCacheDebuger"
            java.lang.String r2 = "mounted"
            boolean r0 = r2.equals(r0)
            r7 = 0
            if (r0 == 0) goto L53
            java.io.File r0 = new java.io.File
            java.io.File r2 = new java.io.File
            java.io.File r3 = android.os.Environment.getExternalStorageDirectory()
            java.lang.String r4 = "Android"
            r2.<init>(r3, r4)
            java.lang.String r3 = "data"
            r0.<init>(r2, r3)
            java.io.File r2 = new java.io.File
            java.io.File r3 = new java.io.File
            java.lang.String r4 = r9.getPackageName()
            r3.<init>(r0, r4)
            java.lang.String r0 = "cache"
            r2.<init>(r3, r0)
            boolean r0 = r2.exists()
            if (r0 != 0) goto L54
            boolean r0 = r2.mkdirs()
            if (r0 != 0) goto L54
            java.lang.String r0 = "Unable to create external cache directory"
            p005b.p172h.p173a.C1817f.m1165b(r1, r0)
        L53:
            r2 = r7
        L54:
            if (r2 != 0) goto L5a
            java.io.File r2 = r9.getCacheDir()
        L5a:
            if (r2 != 0) goto L90
            java.lang.String r0 = "/data/data/"
            java.lang.StringBuilder r0 = p005b.p131d.p132a.p133a.C1499a.m586H(r0)
            java.lang.String r9 = r9.getPackageName()
            r0.append(r9)
            java.lang.String r9 = "/cache/"
            r0.append(r9)
            java.lang.String r9 = r0.toString()
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r2 = "Can't define system cache directory! '"
            r0.append(r2)
            r0.append(r9)
            java.lang.String r2 = "%s' will be used."
            r0.append(r2)
            java.lang.String r0 = r0.toString()
            p005b.p172h.p173a.C1817f.m1165b(r1, r0)
            java.io.File r2 = new java.io.File
            r2.<init>(r9)
        L90:
            java.io.File r9 = new java.io.File
            java.lang.String r0 = "video-cache"
            r9.<init>(r2, r0)
            b.h.a.r.g r4 = new b.h.a.r.g
            r0 = 536870912(0x20000000, double:2.65249474E-315)
            r4.<init>(r0)
            b.h.a.r.f r3 = new b.h.a.r.f
            r3.<init>()
            b.y.a.e.c r6 = r8.f8029i
            java.util.Objects.requireNonNull(r6)
            r8.f8026f = r10
            b.h.a.c r9 = new b.h.a.c
            r1 = r9
            r2 = r10
            r1.<init>(r2, r3, r4, r5, r6)
            b.h.a.g r10 = new b.h.a.g
            r10.<init>(r9, r7)
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p362y.p363a.p365e.C2923b.m3400d(android.content.Context, java.io.File):b.h.a.g");
    }

    @Override // p005b.p362y.p363a.p365e.InterfaceC2922a
    public void doCacheLogic(Context context, IMediaPlayer iMediaPlayer, String str, Map<String, String> map, File file) {
        Map<String, String> map2 = C2924c.f8030a;
        map2.clear();
        if (map != null) {
            map2.putAll(map);
        }
        if (str.startsWith("http") && !str.contains("127.0.0.1") && !str.contains(".m3u8")) {
            C1818g m3398b = m3398b(context.getApplicationContext(), file);
            String m1168c = m3398b.m1168c(str);
            boolean z = !m1168c.startsWith("http");
            this.f8027g = z;
            if (!z) {
                Object[] objArr = {this, str};
                for (int i2 = 0; i2 < 2; i2++) {
                    Objects.requireNonNull(objArr[i2]);
                }
                synchronized (m3398b.f2788a) {
                    try {
                        m3398b.m1166a(str).f2803d.add(this);
                    } catch (C1825n e2) {
                        C1817f.m1165b("Error registering cache listener", e2.getMessage());
                    }
                }
            }
            str = m1168c;
        } else if (!str.startsWith("http") && !str.startsWith("rtmp") && !str.startsWith("rtsp") && !str.contains(".m3u8")) {
            this.f8027g = true;
        }
        try {
            iMediaPlayer.setDataSource(context, Uri.parse(str), map);
        } catch (IOException e3) {
            e3.printStackTrace();
        }
    }

    @Override // p005b.p362y.p363a.p365e.InterfaceC2922a
    public boolean hadCached() {
        return this.f8027g;
    }

    @Override // p005b.p362y.p363a.p365e.InterfaceC2922a
    public void release() {
        C1818g c1818g = this.f8025e;
        if (c1818g != null) {
            try {
                c1818g.m1172g(this);
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    @Override // p005b.p362y.p363a.p365e.InterfaceC2922a
    public void setCacheAvailableListener(InterfaceC2922a.a aVar) {
        this.f8028h = aVar;
    }
}

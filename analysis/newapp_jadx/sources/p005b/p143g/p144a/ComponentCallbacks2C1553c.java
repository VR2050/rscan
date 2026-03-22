package p005b.p143g.p144a;

import android.R;
import android.app.Activity;
import android.app.Fragment;
import android.content.ComponentCallbacks2;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.AssetFileDescriptor;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import androidx.annotation.GuardedBy;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.FragmentActivity;
import com.bumptech.glide.GeneratedAppGlideModule;
import com.bumptech.glide.load.ImageHeaderParser;
import com.bumptech.glide.load.resource.gif.GifDrawable;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p146l.InterfaceC1564a;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p148s.C1597k;
import p005b.p143g.p144a.p147m.p148s.C1599m;
import p005b.p143g.p144a.p147m.p150t.C1644l;
import p005b.p143g.p144a.p147m.p150t.p151c0.C1615e;
import p005b.p143g.p144a.p147m.p150t.p151c0.C1619i;
import p005b.p143g.p144a.p147m.p150t.p151c0.C1620j;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;
import p005b.p143g.p144a.p147m.p150t.p152d0.C1631g;
import p005b.p143g.p144a.p147m.p150t.p152d0.C1632h;
import p005b.p143g.p144a.p147m.p150t.p152d0.C1634j;
import p005b.p143g.p144a.p147m.p150t.p152d0.InterfaceC1633i;
import p005b.p143g.p144a.p147m.p150t.p153e0.ExecutorServiceC1637a;
import p005b.p143g.p144a.p147m.p154u.C1659a;
import p005b.p143g.p144a.p147m.p154u.C1660b;
import p005b.p143g.p144a.p147m.p154u.C1661c;
import p005b.p143g.p144a.p147m.p154u.C1662d;
import p005b.p143g.p144a.p147m.p154u.C1663e;
import p005b.p143g.p144a.p147m.p154u.C1664f;
import p005b.p143g.p144a.p147m.p154u.C1665g;
import p005b.p143g.p144a.p147m.p154u.C1669k;
import p005b.p143g.p144a.p147m.p154u.C1677s;
import p005b.p143g.p144a.p147m.p154u.C1678t;
import p005b.p143g.p144a.p147m.p154u.C1679u;
import p005b.p143g.p144a.p147m.p154u.C1680v;
import p005b.p143g.p144a.p147m.p154u.C1681w;
import p005b.p143g.p144a.p147m.p154u.C1682x;
import p005b.p143g.p144a.p147m.p154u.p155y.C1683a;
import p005b.p143g.p144a.p147m.p154u.p155y.C1684b;
import p005b.p143g.p144a.p147m.p154u.p155y.C1685c;
import p005b.p143g.p144a.p147m.p154u.p155y.C1686d;
import p005b.p143g.p144a.p147m.p154u.p155y.C1687e;
import p005b.p143g.p144a.p147m.p154u.p155y.C1688f;
import p005b.p143g.p144a.p147m.p156v.p157c.C1691a;
import p005b.p143g.p144a.p147m.p156v.p157c.C1692a0;
import p005b.p143g.p144a.p147m.p156v.p157c.C1693b;
import p005b.p143g.p144a.p147m.p156v.p157c.C1695c;
import p005b.p143g.p144a.p147m.p156v.p157c.C1696c0;
import p005b.p143g.p144a.p147m.p156v.p157c.C1698d0;
import p005b.p143g.p144a.p147m.p156v.p157c.C1702g;
import p005b.p143g.p144a.p147m.p156v.p157c.C1703h;
import p005b.p143g.p144a.p147m.p156v.p157c.C1707l;
import p005b.p143g.p144a.p147m.p156v.p157c.C1709n;
import p005b.p143g.p144a.p147m.p156v.p157c.C1712q;
import p005b.p143g.p144a.p147m.p156v.p157c.C1716u;
import p005b.p143g.p144a.p147m.p156v.p157c.C1718w;
import p005b.p143g.p144a.p147m.p156v.p157c.C1720y;
import p005b.p143g.p144a.p147m.p156v.p158d.C1722a;
import p005b.p143g.p144a.p147m.p156v.p159e.C1727d;
import p005b.p143g.p144a.p147m.p156v.p159e.C1728e;
import p005b.p143g.p144a.p147m.p156v.p160f.C1729a;
import p005b.p143g.p144a.p147m.p156v.p161g.C1731a;
import p005b.p143g.p144a.p147m.p156v.p161g.C1733c;
import p005b.p143g.p144a.p147m.p156v.p161g.C1737g;
import p005b.p143g.p144a.p147m.p156v.p161g.C1739i;
import p005b.p143g.p144a.p147m.p156v.p162h.C1740a;
import p005b.p143g.p144a.p147m.p156v.p162h.C1741b;
import p005b.p143g.p144a.p147m.p156v.p162h.C1742c;
import p005b.p143g.p144a.p147m.p156v.p162h.C1743d;
import p005b.p143g.p144a.p163n.C1752f;
import p005b.p143g.p144a.p163n.C1758l;
import p005b.p143g.p144a.p163n.InterfaceC1750d;
import p005b.p143g.p144a.p164o.C1766e;
import p005b.p143g.p144a.p164o.InterfaceC1764c;
import p005b.p143g.p144a.p165p.C1769b;
import p005b.p143g.p144a.p166q.InterfaceC1778e;
import p005b.p143g.p144a.p166q.p167i.C1788g;
import p005b.p143g.p144a.p170s.C1804f;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.c */
/* loaded from: classes.dex */
public class ComponentCallbacks2C1553c implements ComponentCallbacks2 {

    /* renamed from: c */
    public static volatile ComponentCallbacks2C1553c f1808c;

    /* renamed from: e */
    public static volatile boolean f1809e;

    /* renamed from: f */
    public final C1644l f1810f;

    /* renamed from: g */
    public final InterfaceC1614d f1811g;

    /* renamed from: h */
    public final InterfaceC1633i f1812h;

    /* renamed from: i */
    public final C1555e f1813i;

    /* renamed from: j */
    public final C1557g f1814j;

    /* renamed from: k */
    public final InterfaceC1612b f1815k;

    /* renamed from: l */
    public final C1758l f1816l;

    /* renamed from: m */
    public final InterfaceC1750d f1817m;

    /* renamed from: n */
    public final List<ComponentCallbacks2C1559i> f1818n = new ArrayList();

    /* renamed from: b.g.a.c$a */
    public interface a {
    }

    public ComponentCallbacks2C1553c(@NonNull Context context, @NonNull C1644l c1644l, @NonNull InterfaceC1633i interfaceC1633i, @NonNull InterfaceC1614d interfaceC1614d, @NonNull InterfaceC1612b interfaceC1612b, @NonNull C1758l c1758l, @NonNull InterfaceC1750d interfaceC1750d, int i2, @NonNull a aVar, @NonNull Map<Class<?>, AbstractC1560j<?, ?>> map, @NonNull List<InterfaceC1778e<Object>> list, boolean z, boolean z2) {
        InterfaceC1584p c1702g;
        InterfaceC1584p c1692a0;
        this.f1810f = c1644l;
        this.f1811g = interfaceC1614d;
        this.f1815k = interfaceC1612b;
        this.f1812h = interfaceC1633i;
        this.f1816l = c1758l;
        this.f1817m = interfaceC1750d;
        Resources resources = context.getResources();
        C1557g c1557g = new C1557g();
        this.f1814j = c1557g;
        C1707l c1707l = new C1707l();
        C1769b c1769b = c1557g.f1856g;
        synchronized (c1769b) {
            c1769b.f2639a.add(c1707l);
        }
        int i3 = Build.VERSION.SDK_INT;
        if (i3 >= 27) {
            C1712q c1712q = new C1712q();
            C1769b c1769b2 = c1557g.f1856g;
            synchronized (c1769b2) {
                c1769b2.f2639a.add(c1712q);
            }
        }
        List<ImageHeaderParser> m747e = c1557g.m747e();
        C1731a c1731a = new C1731a(context, m747e, interfaceC1614d, interfaceC1612b);
        C1698d0 c1698d0 = new C1698d0(interfaceC1614d, new C1698d0.g());
        C1709n c1709n = new C1709n(c1557g.m747e(), resources.getDisplayMetrics(), interfaceC1614d, interfaceC1612b);
        if (!z2 || i3 < 28) {
            c1702g = new C1702g(c1709n);
            c1692a0 = new C1692a0(c1709n, interfaceC1612b);
        } else {
            c1692a0 = new C1716u();
            c1702g = new C1703h();
        }
        C1727d c1727d = new C1727d(context);
        C1677s.c cVar = new C1677s.c(resources);
        C1677s.d dVar = new C1677s.d(resources);
        C1677s.b bVar = new C1677s.b(resources);
        C1677s.a aVar2 = new C1677s.a(resources);
        C1695c c1695c = new C1695c(interfaceC1612b);
        C1740a c1740a = new C1740a();
        C1743d c1743d = new C1743d();
        ContentResolver contentResolver = context.getContentResolver();
        c1557g.m743a(ByteBuffer.class, new C1661c());
        c1557g.m743a(InputStream.class, new C1678t(interfaceC1612b));
        c1557g.m746d("Bitmap", ByteBuffer.class, Bitmap.class, c1702g);
        c1557g.m746d("Bitmap", InputStream.class, Bitmap.class, c1692a0);
        c1557g.m746d("Bitmap", ParcelFileDescriptor.class, Bitmap.class, new C1718w(c1709n));
        c1557g.m746d("Bitmap", ParcelFileDescriptor.class, Bitmap.class, c1698d0);
        c1557g.m746d("Bitmap", AssetFileDescriptor.class, Bitmap.class, new C1698d0(interfaceC1614d, new C1698d0.c(null)));
        C1680v.a<?> aVar3 = C1680v.a.f2415a;
        c1557g.m745c(Bitmap.class, Bitmap.class, aVar3);
        c1557g.m746d("Bitmap", Bitmap.class, Bitmap.class, new C1696c0());
        c1557g.m744b(Bitmap.class, c1695c);
        c1557g.m746d("BitmapDrawable", ByteBuffer.class, BitmapDrawable.class, new C1691a(resources, c1702g));
        c1557g.m746d("BitmapDrawable", InputStream.class, BitmapDrawable.class, new C1691a(resources, c1692a0));
        c1557g.m746d("BitmapDrawable", ParcelFileDescriptor.class, BitmapDrawable.class, new C1691a(resources, c1698d0));
        c1557g.m744b(BitmapDrawable.class, new C1693b(interfaceC1614d, c1695c));
        c1557g.m746d("Gif", InputStream.class, GifDrawable.class, new C1739i(m747e, c1731a, interfaceC1612b));
        c1557g.m746d("Gif", ByteBuffer.class, GifDrawable.class, c1731a);
        c1557g.m744b(GifDrawable.class, new C1733c());
        c1557g.m745c(InterfaceC1564a.class, InterfaceC1564a.class, aVar3);
        c1557g.m746d("Bitmap", InterfaceC1564a.class, Bitmap.class, new C1737g(interfaceC1614d));
        c1557g.m746d("legacy_append", Uri.class, Drawable.class, c1727d);
        c1557g.m746d("legacy_append", Uri.class, Bitmap.class, new C1720y(c1727d, interfaceC1614d));
        c1557g.m749g(new C1722a.a());
        c1557g.m745c(File.class, ByteBuffer.class, new C1662d.b());
        c1557g.m745c(File.class, InputStream.class, new C1664f.e());
        c1557g.m746d("legacy_append", File.class, File.class, new C1729a());
        c1557g.m745c(File.class, ParcelFileDescriptor.class, new C1664f.b());
        c1557g.m745c(File.class, File.class, aVar3);
        c1557g.m749g(new C1597k.a(interfaceC1612b));
        c1557g.m749g(new C1599m.a());
        Class cls = Integer.TYPE;
        c1557g.m745c(cls, InputStream.class, cVar);
        c1557g.m745c(cls, ParcelFileDescriptor.class, bVar);
        c1557g.m745c(Integer.class, InputStream.class, cVar);
        c1557g.m745c(Integer.class, ParcelFileDescriptor.class, bVar);
        c1557g.m745c(Integer.class, Uri.class, dVar);
        c1557g.m745c(cls, AssetFileDescriptor.class, aVar2);
        c1557g.m745c(Integer.class, AssetFileDescriptor.class, aVar2);
        c1557g.m745c(cls, Uri.class, dVar);
        c1557g.m745c(String.class, InputStream.class, new C1663e.c());
        c1557g.m745c(Uri.class, InputStream.class, new C1663e.c());
        c1557g.m745c(String.class, InputStream.class, new C1679u.c());
        c1557g.m745c(String.class, ParcelFileDescriptor.class, new C1679u.b());
        c1557g.m745c(String.class, AssetFileDescriptor.class, new C1679u.a());
        c1557g.m745c(Uri.class, InputStream.class, new C1684b.a());
        c1557g.m745c(Uri.class, InputStream.class, new C1659a.c(context.getAssets()));
        c1557g.m745c(Uri.class, ParcelFileDescriptor.class, new C1659a.b(context.getAssets()));
        c1557g.m745c(Uri.class, InputStream.class, new C1685c.a(context));
        c1557g.m745c(Uri.class, InputStream.class, new C1686d.a(context));
        if (i3 >= 29) {
            c1557g.m745c(Uri.class, InputStream.class, new C1687e.c(context));
            c1557g.m745c(Uri.class, ParcelFileDescriptor.class, new C1687e.b(context));
        }
        c1557g.m745c(Uri.class, InputStream.class, new C1681w.d(contentResolver));
        c1557g.m745c(Uri.class, ParcelFileDescriptor.class, new C1681w.b(contentResolver));
        c1557g.m745c(Uri.class, AssetFileDescriptor.class, new C1681w.a(contentResolver));
        c1557g.m745c(Uri.class, InputStream.class, new C1682x.a());
        c1557g.m745c(URL.class, InputStream.class, new C1688f.a());
        c1557g.m745c(Uri.class, File.class, new C1669k.a(context));
        c1557g.m745c(C1665g.class, InputStream.class, new C1683a.a());
        c1557g.m745c(byte[].class, ByteBuffer.class, new C1660b.a());
        c1557g.m745c(byte[].class, InputStream.class, new C1660b.d());
        c1557g.m745c(Uri.class, Uri.class, aVar3);
        c1557g.m745c(Drawable.class, Drawable.class, aVar3);
        c1557g.m746d("legacy_append", Drawable.class, Drawable.class, new C1728e());
        c1557g.m750h(Bitmap.class, BitmapDrawable.class, new C1741b(resources));
        c1557g.m750h(Bitmap.class, byte[].class, c1740a);
        c1557g.m750h(Drawable.class, byte[].class, new C1742c(interfaceC1614d, c1740a, c1743d));
        c1557g.m750h(GifDrawable.class, byte[].class, c1743d);
        if (i3 >= 23) {
            C1698d0 c1698d02 = new C1698d0(interfaceC1614d, new C1698d0.d());
            c1557g.m746d("legacy_append", ByteBuffer.class, Bitmap.class, c1698d02);
            c1557g.m746d("legacy_append", ByteBuffer.class, BitmapDrawable.class, new C1691a(resources, c1698d02));
        }
        this.f1813i = new C1555e(context, interfaceC1612b, c1557g, new C1788g(), aVar, map, list, c1644l, z, i2);
    }

    @GuardedBy("Glide.class")
    /* renamed from: a */
    public static void m734a(@NonNull Context context, @Nullable GeneratedAppGlideModule generatedAppGlideModule) {
        List<InterfaceC1764c> list;
        if (f1809e) {
            throw new IllegalStateException("You cannot call Glide.get() in registerComponents(), use the provided Glide instance instead");
        }
        f1809e = true;
        C1554d c1554d = new C1554d();
        Context applicationContext = context.getApplicationContext();
        List emptyList = Collections.emptyList();
        if (generatedAppGlideModule == null || generatedAppGlideModule.mo1062c()) {
            Log.isLoggable("ManifestParser", 3);
            ArrayList arrayList = new ArrayList();
            try {
                ApplicationInfo applicationInfo = applicationContext.getPackageManager().getApplicationInfo(applicationContext.getPackageName(), 128);
                if (applicationInfo.metaData == null) {
                    Log.isLoggable("ManifestParser", 3);
                } else {
                    if (Log.isLoggable("ManifestParser", 2)) {
                        String str = "Got app info metadata: " + applicationInfo.metaData;
                    }
                    for (String str2 : applicationInfo.metaData.keySet()) {
                        if ("GlideModule".equals(applicationInfo.metaData.get(str2))) {
                            arrayList.add(C1766e.m1064a(str2));
                            Log.isLoggable("ManifestParser", 3);
                        }
                    }
                    Log.isLoggable("ManifestParser", 3);
                }
                list = arrayList;
            } catch (PackageManager.NameNotFoundException e2) {
                throw new RuntimeException("Unable to find metadata to parse GlideModules", e2);
            }
        } else {
            list = emptyList;
        }
        if (generatedAppGlideModule != null && !generatedAppGlideModule.mo3890d().isEmpty()) {
            Set<Class<?>> mo3890d = generatedAppGlideModule.mo3890d();
            Iterator it = list.iterator();
            while (it.hasNext()) {
                InterfaceC1764c interfaceC1764c = (InterfaceC1764c) it.next();
                if (mo3890d.contains(interfaceC1764c.getClass())) {
                    if (Log.isLoggable("Glide", 3)) {
                        String str3 = "AppGlideModule excludes manifest GlideModule: " + interfaceC1764c;
                    }
                    it.remove();
                }
            }
        }
        if (Log.isLoggable("Glide", 3)) {
            for (InterfaceC1764c interfaceC1764c2 : list) {
                StringBuilder m586H = C1499a.m586H("Discovered GlideModule from manifest: ");
                m586H.append(interfaceC1764c2.getClass());
                m586H.toString();
            }
        }
        c1554d.f1831m = generatedAppGlideModule != null ? generatedAppGlideModule.mo3891e() : null;
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            ((InterfaceC1764c) it2.next()).mo1061a(applicationContext, c1554d);
        }
        if (generatedAppGlideModule != null) {
            generatedAppGlideModule.mo1061a(applicationContext, c1554d);
        }
        if (c1554d.f1824f == null) {
            int m904a = ExecutorServiceC1637a.m904a();
            if (TextUtils.isEmpty("source")) {
                throw new IllegalArgumentException(C1499a.m637w("Name must be non-null and non-empty, but given: ", "source"));
            }
            c1554d.f1824f = new ExecutorServiceC1637a(new ThreadPoolExecutor(m904a, m904a, 0L, TimeUnit.MILLISECONDS, new PriorityBlockingQueue(), new ExecutorServiceC1637a.a("source", ExecutorServiceC1637a.b.f2145b, false)));
        }
        if (c1554d.f1825g == null) {
            int i2 = ExecutorServiceC1637a.f2138e;
            if (TextUtils.isEmpty("disk-cache")) {
                throw new IllegalArgumentException(C1499a.m637w("Name must be non-null and non-empty, but given: ", "disk-cache"));
            }
            c1554d.f1825g = new ExecutorServiceC1637a(new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, new PriorityBlockingQueue(), new ExecutorServiceC1637a.a("disk-cache", ExecutorServiceC1637a.b.f2145b, true)));
        }
        if (c1554d.f1832n == null) {
            int i3 = ExecutorServiceC1637a.m904a() >= 4 ? 2 : 1;
            if (TextUtils.isEmpty("animation")) {
                throw new IllegalArgumentException(C1499a.m637w("Name must be non-null and non-empty, but given: ", "animation"));
            }
            c1554d.f1832n = new ExecutorServiceC1637a(new ThreadPoolExecutor(i3, i3, 0L, TimeUnit.MILLISECONDS, new PriorityBlockingQueue(), new ExecutorServiceC1637a.a("animation", ExecutorServiceC1637a.b.f2145b, true)));
        }
        if (c1554d.f1827i == null) {
            c1554d.f1827i = new C1634j(new C1634j.a(applicationContext));
        }
        if (c1554d.f1828j == null) {
            c1554d.f1828j = new C1752f();
        }
        if (c1554d.f1821c == null) {
            int i4 = c1554d.f1827i.f2120a;
            if (i4 > 0) {
                c1554d.f1821c = new C1620j(i4);
            } else {
                c1554d.f1821c = new C1615e();
            }
        }
        if (c1554d.f1822d == null) {
            c1554d.f1822d = new C1619i(c1554d.f1827i.f2123d);
        }
        if (c1554d.f1823e == null) {
            c1554d.f1823e = new C1632h(c1554d.f1827i.f2121b);
        }
        if (c1554d.f1826h == null) {
            c1554d.f1826h = new C1631g(applicationContext);
        }
        if (c1554d.f1820b == null) {
            c1554d.f1820b = new C1644l(c1554d.f1823e, c1554d.f1826h, c1554d.f1825g, c1554d.f1824f, new ExecutorServiceC1637a(new ThreadPoolExecutor(0, Integer.MAX_VALUE, ExecutorServiceC1637a.f2137c, TimeUnit.MILLISECONDS, new SynchronousQueue(), new ExecutorServiceC1637a.a("source-unlimited", ExecutorServiceC1637a.b.f2145b, false))), c1554d.f1832n, false);
        }
        List<InterfaceC1778e<Object>> list2 = c1554d.f1833o;
        if (list2 == null) {
            c1554d.f1833o = Collections.emptyList();
        } else {
            c1554d.f1833o = Collections.unmodifiableList(list2);
        }
        ComponentCallbacks2C1553c componentCallbacks2C1553c = new ComponentCallbacks2C1553c(applicationContext, c1554d.f1820b, c1554d.f1823e, c1554d.f1821c, c1554d.f1822d, new C1758l(c1554d.f1831m), c1554d.f1828j, c1554d.f1829k, c1554d.f1830l, c1554d.f1819a, c1554d.f1833o, false, false);
        for (InterfaceC1764c interfaceC1764c3 : list) {
            try {
                interfaceC1764c3.mo1063b(applicationContext, componentCallbacks2C1553c, componentCallbacks2C1553c.f1814j);
            } catch (AbstractMethodError e3) {
                StringBuilder m586H2 = C1499a.m586H("Attempting to register a Glide v3 module. If you see this, you or one of your dependencies may be including Glide v3 even though you're using Glide v4. You'll need to find and remove (or update) the offending dependency. The v3 module name is: ");
                m586H2.append(interfaceC1764c3.getClass().getName());
                throw new IllegalStateException(m586H2.toString(), e3);
            }
        }
        if (generatedAppGlideModule != null) {
            generatedAppGlideModule.mo1063b(applicationContext, componentCallbacks2C1553c, componentCallbacks2C1553c.f1814j);
        }
        applicationContext.registerComponentCallbacks(componentCallbacks2C1553c);
        f1808c = componentCallbacks2C1553c;
        f1809e = false;
    }

    @NonNull
    /* renamed from: d */
    public static ComponentCallbacks2C1553c m735d(@NonNull Context context) {
        if (f1808c == null) {
            GeneratedAppGlideModule generatedAppGlideModule = null;
            try {
                generatedAppGlideModule = (GeneratedAppGlideModule) Class.forName("com.bumptech.glide.GeneratedAppGlideModuleImpl").getDeclaredConstructor(Context.class).newInstance(context.getApplicationContext().getApplicationContext());
            } catch (ClassNotFoundException unused) {
                Log.isLoggable("Glide", 5);
            } catch (IllegalAccessException e2) {
                m737f(e2);
                throw null;
            } catch (InstantiationException e3) {
                m737f(e3);
                throw null;
            } catch (NoSuchMethodException e4) {
                m737f(e4);
                throw null;
            } catch (InvocationTargetException e5) {
                m737f(e5);
                throw null;
            }
            synchronized (ComponentCallbacks2C1553c.class) {
                if (f1808c == null) {
                    m734a(context, generatedAppGlideModule);
                }
            }
        }
        return f1808c;
    }

    @NonNull
    /* renamed from: e */
    public static C1758l m736e(@Nullable Context context) {
        Objects.requireNonNull(context, "You cannot start a load on a not yet attached View or a Fragment where getActivity() returns null (which usually occurs when getActivity() is called before the Fragment is attached or after the Fragment is destroyed).");
        return m735d(context).f1816l;
    }

    /* renamed from: f */
    public static void m737f(Exception exc) {
        throw new IllegalStateException("GeneratedAppGlideModuleImpl is implemented incorrectly. If you've manually implemented this class, remove your implementation. The Annotation processor will generate a correct implementation.", exc);
    }

    @NonNull
    /* renamed from: h */
    public static ComponentCallbacks2C1559i m738h(@NonNull Context context) {
        Objects.requireNonNull(context, "You cannot start a load on a not yet attached View or a Fragment where getActivity() returns null (which usually occurs when getActivity() is called before the Fragment is attached or after the Fragment is destroyed).");
        return m735d(context).f1816l.m1054f(context);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @NonNull
    /* renamed from: i */
    public static ComponentCallbacks2C1559i m739i(@NonNull View view) {
        C1758l m736e = m736e(view.getContext());
        Objects.requireNonNull(m736e);
        if (C1807i.m1150g()) {
            return m736e.m1054f(view.getContext().getApplicationContext());
        }
        Objects.requireNonNull(view.getContext(), "Unable to obtain a request manager for a view without a Context");
        Activity m1048a = C1758l.m1048a(view.getContext());
        if (m1048a == null) {
            return m736e.m1054f(view.getContext().getApplicationContext());
        }
        Fragment fragment = null;
        androidx.fragment.app.Fragment fragment2 = null;
        if (m1048a instanceof FragmentActivity) {
            FragmentActivity fragmentActivity = (FragmentActivity) m1048a;
            m736e.f2629j.clear();
            C1758l.m1049c(fragmentActivity.getSupportFragmentManager().getFragments(), m736e.f2629j);
            View findViewById = fragmentActivity.findViewById(R.id.content);
            while (!view.equals(findViewById) && (fragment2 = m736e.f2629j.get(view)) == null && (view.getParent() instanceof View)) {
                view = (View) view.getParent();
            }
            m736e.f2629j.clear();
            return fragment2 != null ? m736e.m1055g(fragment2) : m736e.m1056h(fragmentActivity);
        }
        m736e.f2630k.clear();
        m736e.m1051b(m1048a.getFragmentManager(), m736e.f2630k);
        View findViewById2 = m1048a.findViewById(R.id.content);
        while (!view.equals(findViewById2) && (fragment = m736e.f2630k.get(view)) == null && (view.getParent() instanceof View)) {
            view = (View) view.getParent();
        }
        m736e.f2630k.clear();
        if (fragment == null) {
            return m736e.m1053e(m1048a);
        }
        if (fragment.getActivity() != null) {
            return !C1807i.m1150g() ? m736e.m1052d(fragment.getActivity(), fragment.getChildFragmentManager(), fragment, fragment.isVisible()) : m736e.m1054f(fragment.getActivity().getApplicationContext());
        }
        throw new IllegalArgumentException("You cannot start a load on a fragment before it is attached");
    }

    /* renamed from: b */
    public void m740b() {
        if (!C1807i.m1150g()) {
            throw new IllegalArgumentException("You must call this method on a background thread");
        }
        this.f1810f.f2232g.m938a().clear();
    }

    /* renamed from: c */
    public void m741c() {
        C1807i.m1144a();
        ((C1804f) this.f1812h).m1141e(0L);
        this.f1811g.mo868b();
        this.f1815k.mo861b();
    }

    /* renamed from: g */
    public void m742g(int i2) {
        long j2;
        C1807i.m1144a();
        Iterator<ComponentCallbacks2C1559i> it = this.f1818n.iterator();
        while (it.hasNext()) {
            Objects.requireNonNull(it.next());
        }
        C1632h c1632h = (C1632h) this.f1812h;
        Objects.requireNonNull(c1632h);
        if (i2 >= 40) {
            c1632h.m1141e(0L);
        } else if (i2 >= 20 || i2 == 15) {
            synchronized (c1632h) {
                j2 = c1632h.f2761b;
            }
            c1632h.m1141e(j2 / 2);
        }
        this.f1811g.mo867a(i2);
        this.f1815k.mo860a(i2);
    }

    @Override // android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration configuration) {
    }

    @Override // android.content.ComponentCallbacks
    public void onLowMemory() {
        m741c();
    }

    @Override // android.content.ComponentCallbacks2
    public void onTrimMemory(int i2) {
        m742g(i2);
    }
}

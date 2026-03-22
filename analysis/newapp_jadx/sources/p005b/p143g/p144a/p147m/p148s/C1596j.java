package p005b.p143g.p144a.p147m.p148s;

import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Map;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.C1573e;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p154u.C1665g;
import p005b.p143g.p144a.p170s.C1800b;
import p005b.p143g.p144a.p170s.C1803e;

/* renamed from: b.g.a.m.s.j */
/* loaded from: classes.dex */
public class C1596j implements InterfaceC1590d<InputStream> {

    /* renamed from: c */
    @VisibleForTesting
    public static final b f2014c = new a();

    /* renamed from: e */
    public final C1665g f2015e;

    /* renamed from: f */
    public final int f2016f;

    /* renamed from: g */
    public HttpURLConnection f2017g;

    /* renamed from: h */
    public InputStream f2018h;

    /* renamed from: i */
    public volatile boolean f2019i;

    /* renamed from: b.g.a.m.s.j$a */
    public static class a implements b {
    }

    /* renamed from: b.g.a.m.s.j$b */
    public interface b {
    }

    public C1596j(C1665g c1665g, int i2) {
        this.f2015e = c1665g;
        this.f2016f = i2;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    @NonNull
    /* renamed from: a */
    public Class<InputStream> mo832a() {
        return InputStream.class;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    /* renamed from: b */
    public void mo835b() {
        InputStream inputStream = this.f2018h;
        if (inputStream != null) {
            try {
                inputStream.close();
            } catch (IOException unused) {
            }
        }
        HttpURLConnection httpURLConnection = this.f2017g;
        if (httpURLConnection != null) {
            httpURLConnection.disconnect();
        }
        this.f2017g = null;
    }

    /* renamed from: c */
    public final InputStream m845c(URL url, int i2, URL url2, Map<String, String> map) {
        if (i2 >= 5) {
            throw new C1573e("Too many (> 5) redirects!");
        }
        if (url2 != null) {
            try {
                if (url.toURI().equals(url2.toURI())) {
                    throw new C1573e("In re-direct loop");
                }
            } catch (URISyntaxException unused) {
            }
        }
        this.f2017g = (HttpURLConnection) url.openConnection();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            this.f2017g.addRequestProperty(entry.getKey(), entry.getValue());
        }
        this.f2017g.setConnectTimeout(this.f2016f);
        this.f2017g.setReadTimeout(this.f2016f);
        this.f2017g.setUseCaches(false);
        this.f2017g.setDoInput(true);
        this.f2017g.setInstanceFollowRedirects(false);
        this.f2017g.connect();
        this.f2018h = this.f2017g.getInputStream();
        if (this.f2019i) {
            return null;
        }
        int responseCode = this.f2017g.getResponseCode();
        int i3 = responseCode / 100;
        if (i3 == 2) {
            HttpURLConnection httpURLConnection = this.f2017g;
            if (TextUtils.isEmpty(httpURLConnection.getContentEncoding())) {
                this.f2018h = new C1800b(httpURLConnection.getInputStream(), httpURLConnection.getContentLength());
            } else {
                if (Log.isLoggable("HttpUrlFetcher", 3)) {
                    httpURLConnection.getContentEncoding();
                }
                this.f2018h = httpURLConnection.getInputStream();
            }
            return this.f2018h;
        }
        if (!(i3 == 3)) {
            if (responseCode == -1) {
                throw new C1573e(responseCode);
            }
            throw new C1573e(this.f2017g.getResponseMessage(), responseCode);
        }
        String headerField = this.f2017g.getHeaderField("Location");
        if (TextUtils.isEmpty(headerField)) {
            throw new C1573e("Received empty or null redirect url");
        }
        URL url3 = new URL(url, headerField);
        mo835b();
        return m845c(url3, i2 + 1, url, map);
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    public void cancel() {
        this.f2019i = true;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    /* renamed from: d */
    public void mo837d(@NonNull EnumC1556f enumC1556f, @NonNull InterfaceC1590d.a<? super InputStream> aVar) {
        int i2 = C1803e.f2759b;
        long elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos();
        try {
            try {
                aVar.mo840e(m845c(this.f2015e.m971b(), 0, null, this.f2015e.f2357b.mo972a()));
                if (!Log.isLoggable("HttpUrlFetcher", 2)) {
                    return;
                }
            } catch (IOException e2) {
                Log.isLoggable("HttpUrlFetcher", 3);
                aVar.mo839c(e2);
                if (!Log.isLoggable("HttpUrlFetcher", 2)) {
                    return;
                }
            }
            C1803e.m1138a(elapsedRealtimeNanos);
        } catch (Throwable th) {
            if (Log.isLoggable("HttpUrlFetcher", 2)) {
                C1803e.m1138a(elapsedRealtimeNanos);
            }
            throw th;
        }
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    @NonNull
    public EnumC1569a getDataSource() {
        return EnumC1569a.REMOTE;
    }
}

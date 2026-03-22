package p005b.p143g.p144a.p147m.p154u;

import android.net.Uri;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Objects;
import p005b.p143g.p144a.p147m.InterfaceC1579k;

/* renamed from: b.g.a.m.u.g */
/* loaded from: classes.dex */
public class C1665g implements InterfaceC1579k {

    /* renamed from: b */
    public final InterfaceC1666h f2357b;

    /* renamed from: c */
    @Nullable
    public final URL f2358c;

    /* renamed from: d */
    @Nullable
    public final String f2359d;

    /* renamed from: e */
    @Nullable
    public String f2360e;

    /* renamed from: f */
    @Nullable
    public URL f2361f;

    /* renamed from: g */
    @Nullable
    public volatile byte[] f2362g;

    /* renamed from: h */
    public int f2363h;

    public C1665g(URL url) {
        InterfaceC1666h interfaceC1666h = InterfaceC1666h.f2364a;
        Objects.requireNonNull(url, "Argument must not be null");
        this.f2358c = url;
        this.f2359d = null;
        Objects.requireNonNull(interfaceC1666h, "Argument must not be null");
        this.f2357b = interfaceC1666h;
    }

    /* renamed from: a */
    public String m970a() {
        String str = this.f2359d;
        if (str != null) {
            return str;
        }
        URL url = this.f2358c;
        Objects.requireNonNull(url, "Argument must not be null");
        return url.toString();
    }

    /* renamed from: b */
    public URL m971b() {
        if (this.f2361f == null) {
            if (TextUtils.isEmpty(this.f2360e)) {
                String str = this.f2359d;
                if (TextUtils.isEmpty(str)) {
                    URL url = this.f2358c;
                    Objects.requireNonNull(url, "Argument must not be null");
                    str = url.toString();
                }
                this.f2360e = Uri.encode(str, "@#&=*+-_.,:!?()/~'%;$");
            }
            this.f2361f = new URL(this.f2360e);
        }
        return this.f2361f;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public boolean equals(Object obj) {
        if (!(obj instanceof C1665g)) {
            return false;
        }
        C1665g c1665g = (C1665g) obj;
        return m970a().equals(c1665g.m970a()) && this.f2357b.equals(c1665g.f2357b);
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public int hashCode() {
        if (this.f2363h == 0) {
            int hashCode = m970a().hashCode();
            this.f2363h = hashCode;
            this.f2363h = this.f2357b.hashCode() + (hashCode * 31);
        }
        return this.f2363h;
    }

    public String toString() {
        return m970a();
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public void updateDiskCacheKey(@NonNull MessageDigest messageDigest) {
        if (this.f2362g == null) {
            this.f2362g = m970a().getBytes(InterfaceC1579k.f1988a);
        }
        messageDigest.update(this.f2362g);
    }

    public C1665g(String str) {
        InterfaceC1666h interfaceC1666h = InterfaceC1666h.f2364a;
        this.f2358c = null;
        if (!TextUtils.isEmpty(str)) {
            this.f2359d = str;
            Objects.requireNonNull(interfaceC1666h, "Argument must not be null");
            this.f2357b = interfaceC1666h;
            return;
        }
        throw new IllegalArgumentException("Must not be null or empty");
    }
}

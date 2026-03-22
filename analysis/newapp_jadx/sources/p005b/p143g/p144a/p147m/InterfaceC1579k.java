package p005b.p143g.p144a.p147m;

import androidx.annotation.NonNull;
import java.nio.charset.Charset;
import java.security.MessageDigest;

/* renamed from: b.g.a.m.k */
/* loaded from: classes.dex */
public interface InterfaceC1579k {

    /* renamed from: a */
    public static final Charset f1988a = Charset.forName("UTF-8");

    boolean equals(Object obj);

    int hashCode();

    void updateDiskCacheKey(@NonNull MessageDigest messageDigest);
}

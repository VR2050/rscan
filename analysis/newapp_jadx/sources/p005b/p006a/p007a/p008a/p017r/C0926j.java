package p005b.p006a.p007a.p008a.p017r;

import android.os.Environment;
import com.alibaba.fastjson.support.retrofit.Retrofit2ConverterFactory;
import java.io.File;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p017r.p020m.C0942c;
import p005b.p303q.p304a.p305a.p306a.p307a.C2720c;
import p458k.C4374d;
import p458k.C4375d0;
import p458k.InterfaceC4369a0;
import p458k.p471q0.C4480a;
import p505n.C5031z;
import p505n.InterfaceC4985e;
import p505n.InterfaceC5013h;

/* renamed from: b.a.a.a.r.j */
/* loaded from: classes2.dex */
public final class C0926j {

    /* renamed from: a */
    @NotNull
    public static final C0926j f441a = null;

    /* renamed from: b */
    @NotNull
    public static final C0926j f442b;

    /* renamed from: b.a.a.a.r.j$a */
    public static final class a {

        /* renamed from: a */
        @NotNull
        public static final a f443a = null;

        /* renamed from: b */
        @NotNull
        public static final C0926j f444b = new C0926j();
    }

    static {
        a aVar = a.f443a;
        f442b = a.f444b;
    }

    /* renamed from: a */
    public final C5031z m271a(String str, InterfaceC4985e.a aVar, InterfaceC5013h.a aVar2, C4375d0 c4375d0) {
        C5031z.b bVar = new C5031z.b();
        bVar.m5693b(str);
        bVar.f12973e.add(aVar);
        List<InterfaceC5013h.a> list = bVar.f12972d;
        Objects.requireNonNull(aVar2, "factory == null");
        list.add(aVar2);
        bVar.m5695d(c4375d0);
        C5031z m5694c = bVar.m5694c();
        Intrinsics.checkNotNullExpressionValue(m5694c, "Builder()\n            .baseUrl(baseUrl)\n            .addCallAdapterFactory(callAdapter)\n            .addConverterFactory(converter)\n            .client(client)\n            .build()");
        return m5694c;
    }

    /* renamed from: b */
    public final C4375d0 m272b(long j2, InterfaceC4369a0... interfaceC4369a0Arr) {
        File downloadCacheDirectory = Environment.getDownloadCacheDirectory();
        new CookieManager().setCookiePolicy(CookiePolicy.ACCEPT_ALL);
        C4375d0.a aVar = new C4375d0.a();
        TimeUnit timeUnit = TimeUnit.SECONDS;
        aVar.m4957b(j2, timeUnit);
        aVar.m4959d(j2, timeUnit);
        aVar.m4958c(j2, timeUnit);
        File absoluteFile = downloadCacheDirectory.getAbsoluteFile();
        Intrinsics.checkNotNullExpressionValue(absoluteFile, "cacheFile.absoluteFile");
        aVar.f11397k = new C4374d(absoluteFile, 10485760L);
        aVar.m4956a(new C0942c());
        for (InterfaceC4369a0 interfaceC4369a0 : interfaceC4369a0Arr) {
            aVar.m4956a(interfaceC4369a0);
        }
        return new C4375d0(aVar);
    }

    @NotNull
    /* renamed from: c */
    public final C5031z m273c(@NotNull String baseUrl) {
        Intrinsics.checkNotNullParameter(baseUrl, "baseUrl");
        InterfaceC4985e.a c2720c = new C2720c(null);
        InterfaceC5013h.a create = Retrofit2ConverterFactory.create();
        Intrinsics.checkNotNullExpressionValue(create, "create()");
        C4480a c4480a = new C4480a(new C0923g());
        c4480a.m5264d(C4480a.a.HEADERS);
        return m271a(baseUrl, c2720c, create, m272b(5L, c4480a));
    }
}

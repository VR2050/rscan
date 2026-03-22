package p005b.p006a.p007a.p008a.p017r.p022o;

import android.os.Environment;
import com.alibaba.fastjson.support.retrofit.Retrofit2ConverterFactory;
import java.io.File;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import p005b.p006a.p007a.p008a.p017r.C0923g;
import p005b.p006a.p007a.p008a.p017r.InterfaceC0920d;
import p005b.p006a.p007a.p008a.p017r.p020m.C0942c;
import p005b.p303q.p304a.p305a.p306a.p307a.C2720c;
import p458k.C4374d;
import p458k.C4375d0;
import p458k.p471q0.C4480a;
import p505n.C5031z;

/* renamed from: b.a.a.a.r.o.b */
/* loaded from: classes2.dex */
public final class C0948b extends Lambda implements Function0<InterfaceC0920d> {

    /* renamed from: c */
    public final /* synthetic */ C0949c f486c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0948b(C0949c c0949c) {
        super(0);
        this.f486c = c0949c;
    }

    @Override // kotlin.jvm.functions.Function0
    public InterfaceC0920d invoke() {
        C5031z.b bVar = new C5031z.b();
        bVar.m5693b(this.f486c.f487a);
        bVar.f12973e.add(new C2720c(null));
        bVar.m5692a(Retrofit2ConverterFactory.create());
        Objects.requireNonNull(this.f486c);
        File downloadCacheDirectory = Environment.getDownloadCacheDirectory();
        C4480a c4480a = new C4480a(new C0923g());
        c4480a.m5264d(C4480a.a.BODY);
        C4375d0.a aVar = new C4375d0.a();
        TimeUnit timeUnit = TimeUnit.SECONDS;
        aVar.m4957b(40L, timeUnit);
        aVar.m4959d(40L, timeUnit);
        aVar.m4958c(40L, timeUnit);
        File absoluteFile = downloadCacheDirectory.getAbsoluteFile();
        Intrinsics.checkNotNullExpressionValue(absoluteFile, "sdcache.absoluteFile");
        aVar.f11397k = new C4374d(absoluteFile, 10485760L);
        aVar.m4956a(c4480a);
        aVar.m4956a(new C0942c());
        bVar.m5695d(new C4375d0(aVar));
        return (InterfaceC0920d) bVar.m5694c().m5687b(InterfaceC0920d.class);
    }
}

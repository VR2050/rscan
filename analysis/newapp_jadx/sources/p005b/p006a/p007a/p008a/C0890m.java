package p005b.p006a.p007a.p008a;

import java.io.File;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Lambda;

/* renamed from: b.a.a.a.m */
/* loaded from: classes2.dex */
public final class C0890m extends Lambda implements Function1<String, Unit> {

    /* renamed from: c */
    public final /* synthetic */ File f341c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0890m(File file) {
        super(1);
        this.f341c = file;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(String str) {
        this.f341c.delete();
        return Unit.INSTANCE;
    }
}

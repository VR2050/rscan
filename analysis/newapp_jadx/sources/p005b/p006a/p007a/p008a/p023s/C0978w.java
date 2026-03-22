package p005b.p006a.p007a.p008a.p023s;

import com.jbzd.media.movecartoons.bean.event.EventMusic;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapter;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import p476m.p496b.p497a.C4909c;

/* renamed from: b.a.a.a.s.w */
/* loaded from: classes2.dex */
public final class C0978w extends Lambda implements Function1<NovelChapter, Unit> {

    /* renamed from: c */
    public static final C0978w f595c = new C0978w();

    public C0978w() {
        super(1);
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(NovelChapter novelChapter) {
        NovelChapter item = novelChapter;
        Intrinsics.checkNotNullParameter(item, "item");
        C4909c.m5569b().m5574g(new EventMusic("cantPlay", null, item, 2, null));
        return Unit.INSTANCE;
    }
}

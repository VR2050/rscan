package p005b.p006a.p007a.p008a.p023s;

import com.jbzd.media.movecartoons.bean.response.novel.NovelChapter;
import com.jbzd.media.movecartoons.service.AudioPlayerService;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;

/* renamed from: b.a.a.a.s.u */
/* loaded from: classes2.dex */
public final class C0976u extends Lambda implements Function1<NovelChapter, Unit> {

    /* renamed from: c */
    public final /* synthetic */ AudioPlayerService f593c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0976u(AudioPlayerService audioPlayerService) {
        super(1);
        this.f593c = audioPlayerService;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(NovelChapter novelChapter) {
        NovelChapter it = novelChapter;
        Intrinsics.checkNotNullParameter(it, "it");
        this.f593c.m4204f(it.f10026id.toString(), new C0974s(this.f593c), C0975t.f592c);
        return Unit.INSTANCE;
    }
}

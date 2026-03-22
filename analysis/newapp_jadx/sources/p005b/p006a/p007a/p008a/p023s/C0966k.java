package p005b.p006a.p007a.p008a.p023s;

import com.jbzd.media.movecartoons.bean.event.EventMusic;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapterInfoBean;
import com.jbzd.media.movecartoons.service.AudioPlayerService;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import p476m.p496b.p497a.C4909c;

/* renamed from: b.a.a.a.s.k */
/* loaded from: classes2.dex */
public final class C0966k extends Lambda implements Function0<Unit> {

    /* renamed from: c */
    public final /* synthetic */ AudioPlayerService f582c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0966k(AudioPlayerService audioPlayerService) {
        super(0);
        this.f582c = audioPlayerService;
    }

    @Override // kotlin.jvm.functions.Function0
    public Unit invoke() {
        C4909c m5569b = C4909c.m5569b();
        NovelChapterInfoBean value = this.f582c.m4202d().getValue();
        Intrinsics.checkNotNull(value);
        m5569b.m5574g(new EventMusic("play", null, value.chapter, 2, null));
        AudioPlayerService audioPlayerService = this.f582c;
        NovelChapterInfoBean value2 = audioPlayerService.m4202d().getValue();
        Intrinsics.checkNotNull(value2);
        audioPlayerService.nowPlayingId = value2.chapter.f10026id.toString();
        C4909c.m5569b().m5574g(new EventMusic("progressMax", Integer.valueOf(this.f582c.mediaPlayer.getDuration()), null, 4, null));
        return Unit.INSTANCE;
    }
}

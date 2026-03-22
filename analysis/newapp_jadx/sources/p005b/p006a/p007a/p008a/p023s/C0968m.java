package p005b.p006a.p007a.p008a.p023s;

import com.jbzd.media.movecartoons.bean.response.novel.NovelChapterInfoBean;
import com.jbzd.media.movecartoons.service.AudioPlayerService;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Lambda;

/* renamed from: b.a.a.a.s.m */
/* loaded from: classes2.dex */
public final class C0968m extends Lambda implements Function1<NovelChapterInfoBean, Unit> {

    /* renamed from: c */
    public final /* synthetic */ AudioPlayerService f584c;

    /* renamed from: e */
    public final /* synthetic */ Function0<Unit> f585e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0968m(AudioPlayerService audioPlayerService, Function0<Unit> function0) {
        super(1);
        this.f584c = audioPlayerService;
        this.f585e = function0;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(NovelChapterInfoBean novelChapterInfoBean) {
        this.f584c.m4202d().setValue(novelChapterInfoBean);
        AudioPlayerService audioPlayerService = this.f584c;
        audioPlayerService.mediaPlayer.stop();
        NovelChapterInfoBean value = audioPlayerService.m4202d().getValue();
        if (value != null) {
            audioPlayerService.m4210l(value, new C0966k(audioPlayerService), C0967l.f583c);
        }
        this.f584c.isFromOutside = true;
        this.f585e.invoke();
        return Unit.INSTANCE;
    }
}

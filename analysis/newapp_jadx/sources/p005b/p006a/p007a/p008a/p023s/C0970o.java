package p005b.p006a.p007a.p008a.p023s;

import com.jbzd.media.movecartoons.service.AudioPlayerService;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Lambda;

/* renamed from: b.a.a.a.s.o */
/* loaded from: classes2.dex */
public final class C0970o extends Lambda implements Function0<Unit> {

    /* renamed from: c */
    public final /* synthetic */ AudioPlayerService f587c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0970o(AudioPlayerService audioPlayerService) {
        super(0);
        this.f587c = audioPlayerService;
    }

    @Override // kotlin.jvm.functions.Function0
    public Unit invoke() {
        this.f587c.m4219u(true);
        return Unit.INSTANCE;
    }
}

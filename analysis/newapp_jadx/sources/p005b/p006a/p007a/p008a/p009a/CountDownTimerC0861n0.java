package p005b.p006a.p007a.p008a.p009a;

import android.os.CountDownTimer;
import android.view.View;

/* renamed from: b.a.a.a.a.n0 */
/* loaded from: classes2.dex */
public final class CountDownTimerC0861n0 extends CountDownTimer {

    /* renamed from: a */
    public final /* synthetic */ View f294a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CountDownTimerC0861n0(View view, long j2) {
        super(j2, 100L);
        this.f294a = view;
    }

    @Override // android.os.CountDownTimer
    public void onFinish() {
        this.f294a.setEnabled(true);
    }

    @Override // android.os.CountDownTimer
    public void onTick(long j2) {
    }
}

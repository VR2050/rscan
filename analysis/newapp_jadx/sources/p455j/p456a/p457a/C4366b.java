package p455j.p456a.p457a;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import moe.codeest.enviews.ENDownloadView;

/* renamed from: j.a.a.b */
/* loaded from: classes3.dex */
public class C4366b extends AnimatorListenerAdapter {

    /* renamed from: c */
    public final /* synthetic */ ENDownloadView f11294c;

    public C4366b(ENDownloadView eNDownloadView) {
        this.f11294c = eNDownloadView;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public void onAnimationEnd(Animator animator) {
        ENDownloadView eNDownloadView = this.f11294c;
        eNDownloadView.f12753c = 1;
        ENDownloadView.m5643a(eNDownloadView);
    }
}

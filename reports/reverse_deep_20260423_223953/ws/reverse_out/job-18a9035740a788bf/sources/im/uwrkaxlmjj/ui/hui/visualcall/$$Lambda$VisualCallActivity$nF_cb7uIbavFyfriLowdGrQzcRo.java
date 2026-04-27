package im.uwrkaxlmjj.ui.hui.visualcall;

/* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallActivity$nF_cb7uIbavFyfriLowdGrQzcRo, reason: invalid class name */
/* JADX INFO: compiled from: lambda */
/* JADX INFO: loaded from: classes5.dex */
public final /* synthetic */ class $$Lambda$VisualCallActivity$nF_cb7uIbavFyfriLowdGrQzcRo implements Runnable {
    private final /* synthetic */ VisualCallActivity f$0;

    public /* synthetic */ $$Lambda$VisualCallActivity$nF_cb7uIbavFyfriLowdGrQzcRo(VisualCallActivity visualCallActivity) {
        this.f$0 = visualCallActivity;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.f$0.requestPermission();
    }
}

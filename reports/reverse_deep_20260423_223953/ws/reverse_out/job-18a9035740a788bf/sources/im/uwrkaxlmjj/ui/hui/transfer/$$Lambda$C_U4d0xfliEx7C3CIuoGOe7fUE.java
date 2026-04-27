package im.uwrkaxlmjj.ui.hui.transfer;

/* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.transfer.-$$Lambda$C-_U4d0xfliEx7C3CIuoGOe7fUE, reason: invalid class name */
/* JADX INFO: compiled from: lambda */
/* JADX INFO: loaded from: classes5.dex */
public final /* synthetic */ class $$Lambda$C_U4d0xfliEx7C3CIuoGOe7fUE implements Runnable {
    private final /* synthetic */ TransferStatusActivity f$0;

    public /* synthetic */ $$Lambda$C_U4d0xfliEx7C3CIuoGOe7fUE(TransferStatusActivity transferStatusActivity) {
        this.f$0 = transferStatusActivity;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.f$0.finishFragment();
    }
}

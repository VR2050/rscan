package im.uwrkaxlmjj.ui.hui.contacts;

/* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$Y0dbntpAWzkNmMM36ZiAM0H8ud8, reason: invalid class name */
/* JADX INFO: compiled from: lambda */
/* JADX INFO: loaded from: classes5.dex */
public final /* synthetic */ class $$Lambda$NewFriendsActivity$Y0dbntpAWzkNmMM36ZiAM0H8ud8 implements Runnable {
    private final /* synthetic */ NewFriendsActivity f$0;

    public /* synthetic */ $$Lambda$NewFriendsActivity$Y0dbntpAWzkNmMM36ZiAM0H8ud8(NewFriendsActivity newFriendsActivity) {
        this.f$0 = newFriendsActivity;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.f$0.notifyListUpdate();
    }
}

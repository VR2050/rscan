package im.uwrkaxlmjj.messenger;

/* JADX INFO: renamed from: im.uwrkaxlmjj.messenger.-$$Lambda$MessagesController$d6zltpcX4zlOIu0jQICiA65H4qA, reason: invalid class name */
/* JADX INFO: compiled from: lambda */
/* JADX INFO: loaded from: classes2.dex */
public final /* synthetic */ class $$Lambda$MessagesController$d6zltpcX4zlOIu0jQICiA65H4qA implements Runnable {
    private final /* synthetic */ MessagesController f$0;

    public /* synthetic */ $$Lambda$MessagesController$d6zltpcX4zlOIu0jQICiA65H4qA(MessagesController messagesController) {
        this.f$0 = messagesController;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.f$0.removeProxyDialog();
    }
}

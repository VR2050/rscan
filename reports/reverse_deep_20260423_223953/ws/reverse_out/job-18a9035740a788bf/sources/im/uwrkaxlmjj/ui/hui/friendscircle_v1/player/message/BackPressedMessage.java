package im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.message;

/* JADX INFO: loaded from: classes5.dex */
public class BackPressedMessage extends Message {
    private int mScreenState;

    public BackPressedMessage(int screenState, int hash, String videoUrl) {
        super(hash, videoUrl);
        this.mScreenState = screenState;
    }

    public int getScreenState() {
        return this.mScreenState;
    }
}

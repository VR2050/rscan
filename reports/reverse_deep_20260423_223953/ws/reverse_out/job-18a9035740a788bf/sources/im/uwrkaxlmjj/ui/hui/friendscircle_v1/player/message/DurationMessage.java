package im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.message;

/* JADX INFO: loaded from: classes5.dex */
public class DurationMessage extends Message {
    private int mDuration;

    public DurationMessage(int hash, String videoUrl, int duration) {
        super(hash, videoUrl);
        this.mDuration = duration;
    }

    public int getDuration() {
        return this.mDuration;
    }
}

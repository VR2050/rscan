package im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.message;

/* JADX INFO: loaded from: classes5.dex */
public class Message {
    private int mHash;
    private String mVideoUrl;

    public Message(int hash, String videoUrl) {
        this.mHash = hash;
        this.mVideoUrl = videoUrl;
    }

    public int getHash() {
        return this.mHash;
    }

    public String getVideoUrl() {
        return this.mVideoUrl;
    }
}

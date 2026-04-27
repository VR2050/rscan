package im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.factory;

import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.AbsBaseVideoPlayer;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.MediaVideoPlayer;

/* JADX INFO: loaded from: classes5.dex */
public class MediaPlayerFactory implements IVideoPlayerFactory {
    private boolean mEnableLog;

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.factory.IVideoPlayerFactory
    public AbsBaseVideoPlayer create() {
        return new MediaVideoPlayer(this.mEnableLog);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.factory.IVideoPlayerFactory
    public void logEnable(boolean enableLog) {
        this.mEnableLog = enableLog;
    }
}

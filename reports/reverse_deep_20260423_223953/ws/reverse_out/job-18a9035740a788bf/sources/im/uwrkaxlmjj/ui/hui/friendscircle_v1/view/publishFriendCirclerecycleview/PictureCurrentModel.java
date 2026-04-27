package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.publishFriendCirclerecycleview;

import android.net.Uri;

/* JADX INFO: loaded from: classes5.dex */
public class PictureCurrentModel {
    private String filePath;
    private String type;
    private Uri uri;
    private boolean useSource;

    public Uri getUri() {
        return this.uri;
    }

    public PictureCurrentModel setUri(Uri uri) {
        this.uri = uri;
        return this;
    }

    public String getType() {
        return this.type;
    }

    public PictureCurrentModel setType(String type) {
        this.type = type;
        return this;
    }

    public String getFilePath() {
        return this.filePath;
    }

    public PictureCurrentModel setFilePath(String filePath) {
        this.filePath = filePath;
        return this;
    }

    public boolean isUseSource() {
        return this.useSource;
    }

    public PictureCurrentModel setUseSource(boolean useSource) {
        this.useSource = useSource;
        return this;
    }
}
